package sqlitefinder

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/godaddy/ans/internal/finder/index"
	"github.com/godaddy/ans/internal/finder/project"
)

// Apply writes a page of projected entries into the index inside one
// transaction and returns a report of conditions the caller should log
// (it has the logger; the store does not).
//
// Semantics by lifecycle:
//
//   - ACTIVE: an event's projected entries are the COMPLETE row set for
//     its ansName at that log position. Entries are grouped by
//     (ansName, logId) — one group per event — and each group REPLACES
//     every row for that ansName: all prior rows are deleted (FTS and
//     side rows cleared per rowid) and the group is inserted. This is
//     what keeps a stale endpoint (a (type,url) that changed or was
//     dropped between versions) from lingering ACTIVE and discoverable
//     forever; the old upsert-by-(ans_name,type,url) could only ever add.
//     An event that projects ZERO entries (e.g. a renewal whose endpoints
//     all failed projection) forms no group, so the replace does NOT run
//     and the prior rows survive — deliberately keep-last-known-good
//     rather than blanking an agent on a transient projection miss. A
//     real revoke uses the REVOKED path, not an empty Active set.
//
//   - REVOKED/DEPRECATED: a tombstone suppresses every ACTIVE row for its
//     ansName whose created_at is no newer than the tombstone's.
//
// Replay safety: an ACTIVE group is skipped (not applied) when a row for
// its ansName already carries a non-ACTIVE lifecycle with created_at at
// or after the group's created_at. Without this, a re-delivered (or
// re-fetched) older REGISTERED event would re-surface an agent a newer
// REVOKED already tombstoned. This assumes the feed delivers events in
// log order (REGISTERED before its later REVOKED), which is the feed's
// contract: a tombstone leaves a suppressed row to guard against a
// subsequent older Active replay. It is NOT a marker for the
// tombstone-first case — a REVOKED applied to an index with no prior row
// for the ansName persists nothing, so a later (older) REGISTERED would
// still index the agent. That ordering cannot arise from the in-order
// feed and is not defended against here (no marker rows are inserted).
//
// The whole page commits atomically: a crash mid-page leaves the index at
// the prior cursor and the page replays cleanly.
func (s *Store) Apply(ctx context.Context, entries []project.ProjectedEntry) (index.ApplyReport, error) {
	var report index.ApplyReport
	if len(entries) == 0 {
		return report, nil
	}
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("sqlitefinder: begin apply tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	for _, grp := range groupByEvent(entries) {
		switch grp.lifecycle {
		case project.LifecycleActive:
			if err := replaceActiveSet(ctx, tx, grp); err != nil {
				return index.ApplyReport{}, err
			}
		case project.LifecycleRevoked, project.LifecycleDeprecated:
			pe := grp.entries[0]
			noOp, err := applyTombstone(ctx, tx, pe)
			if err != nil {
				return index.ApplyReport{}, err
			}
			if noOp {
				report.TombstoneNoOps = append(report.TombstoneNoOps, index.TombstoneNoOp{
					AnsName:   pe.AnsName,
					LogID:     pe.LogID,
					CreatedAt: pe.CreatedAt,
				})
			}
		default:
			// The projection layer only ever emits these three lifecycles;
			// an unknown one is a programming error, not a data condition.
			return index.ApplyReport{}, fmt.Errorf("sqlitefinder: unknown lifecycle %q", grp.lifecycle)
		}
	}

	if err := tx.Commit(); err != nil {
		return index.ApplyReport{}, fmt.Errorf("sqlitefinder: commit apply: %w", err)
	}
	committed = true
	return report, nil
}

// eventGroup is the set of projected entries from a single event: they
// share ansName, lifecycle, logId, and createdAt and differ only by the
// endpoint (type, url). For a tombstone the group holds exactly one
// entry.
type eventGroup struct {
	ansName   string
	lifecycle project.Lifecycle
	logID     string
	createdAt string
	entries   []project.ProjectedEntry
}

// groupByEvent splits a page into per-event groups, preserving input
// order so a register-then-renew for the same ansName in one page applies
// in sequence (the later event's row set wins). Grouping is keyed by
// (ansName, logId, lifecycle): one feed event maps to one logId, so this
// is one group per event.
func groupByEvent(entries []project.ProjectedEntry) []eventGroup {
	var groups []eventGroup
	idx := make(map[string]int)
	for _, pe := range entries {
		key := pe.AnsName + "\x00" + pe.LogID + "\x00" + string(pe.Lifecycle)
		if i, ok := idx[key]; ok {
			groups[i].entries = append(groups[i].entries, pe)
			continue
		}
		idx[key] = len(groups)
		groups = append(groups, eventGroup{
			ansName:   pe.AnsName,
			lifecycle: pe.Lifecycle,
			logID:     pe.LogID,
			createdAt: pe.CreatedAt,
			entries:   []project.ProjectedEntry{pe},
		})
	}
	return groups
}

// replaceActiveSet makes the group's entries the complete row set for its
// ansName: it deletes every existing row for the ansName, then inserts
// the group. The replace is skipped when a newer-or-equal tombstone
// already covers the ansName (replay safety — see Apply).
func replaceActiveSet(ctx context.Context, tx *sqlx.Tx, grp eventGroup) error {
	superseded, err := tombstonedAtOrAfter(ctx, tx, grp.ansName, grp.createdAt)
	if err != nil {
		return err
	}
	if superseded {
		// A tombstone at or after this event's time already covers the
		// ansName; re-applying the Active set would un-revoke it.
		return nil
	}

	if err := deleteAllForAnsName(ctx, tx, grp.ansName); err != nil {
		return err
	}
	for _, pe := range dedupByTypeURL(grp.entries) {
		if err := insertActiveRow(ctx, tx, pe); err != nil {
			return err
		}
	}
	return nil
}

// dedupByTypeURL collapses entries that share a (type, url) key, keeping
// the LAST occurrence (last-write-wins). One event can legitimately
// project two entries with the same (type, url): two endpoints of the
// same protocol that both omit metaDataUrl resolve to the identical
// well-known fallback URL, which the projection layer treats as
// contract-legal. Inserting both would violate UNIQUE(ans_name,type,url)
// and fail the whole page — wedging ingestion on a valid registration —
// so the duplicate is folded here, matching the old per-entry
// delete-then-insert that tolerated it as last-write-wins. The surviving
// order follows the first appearance of each key, preserving the
// projection layer's deterministic (identifier, type, url) ordering.
func dedupByTypeURL(entries []project.ProjectedEntry) []project.ProjectedEntry {
	type key struct{ typ, url string }
	pos := make(map[key]int, len(entries))
	out := make([]project.ProjectedEntry, 0, len(entries))
	for _, pe := range entries {
		k := key{pe.Entry.Type, pe.Entry.URL}
		if i, ok := pos[k]; ok {
			out[i] = pe // last-write-wins, in place to keep first-seen order
			continue
		}
		pos[k] = len(out)
		out = append(out, pe)
	}
	return out
}

// tombstonedAtOrAfter reports whether any row for the ansName carries a
// non-ACTIVE lifecycle with created_at >= the given time — i.e. a
// revoke/deprecate that an Active replay must not override.
func tombstonedAtOrAfter(ctx context.Context, tx *sqlx.Tx, ansName, createdAt string) (bool, error) {
	var n int
	if err := tx.GetContext(ctx, &n, `
        SELECT COUNT(*) FROM finder_entries
         WHERE ans_name = ? AND lifecycle <> 'ACTIVE' AND created_at >= ?`,
		ansName, createdAt); err != nil {
		return false, fmt.Errorf("sqlitefinder: check existing tombstone: %w", err)
	}
	return n > 0, nil
}

// deleteAllForAnsName removes every row for an ansName along with each
// row's FTS and side-table rows. Used by the Active replace path so a
// renewal that drops or changes an endpoint does not leave the old row
// behind.
func deleteAllForAnsName(ctx context.Context, tx *sqlx.Tx, ansName string) error {
	rowids, err := rowidsForAnsName(ctx, tx, ansName)
	if err != nil {
		return err
	}
	for _, rowid := range rowids {
		if err := clearSideAndFTS(ctx, tx, rowid); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM finder_entries WHERE ans_name = ?`, ansName); err != nil {
		return fmt.Errorf("sqlitefinder: delete rows for ansName: %w", err)
	}
	return nil
}

// insertActiveRow inserts one Active projected entry plus its side-tables
// and FTS row. The caller has already cleared the ansName's prior rows.
func insertActiveRow(ctx context.Context, tx *sqlx.Tx, pe project.ProjectedEntry) error {
	entryJSON, err := json.Marshal(pe.Entry)
	if err != nil {
		return fmt.Errorf("sqlitefinder: marshal entry: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
        INSERT INTO finder_entries (
            ans_name, type, url, identifier, publisher, agent_id, log_id,
            display_name, description, version, updated_at,
            lifecycle, created_at, expires_at, entry_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		pe.AnsName, pe.Entry.Type, pe.Entry.URL, pe.Entry.Identifier,
		publisherFromURN(pe.Entry.Identifier), pe.AgentID, pe.LogID,
		pe.Entry.DisplayName, pe.Entry.Description, pe.Entry.Version, pe.Entry.UpdatedAt,
		string(project.LifecycleActive), pe.CreatedAt, pe.ExpiresAt, string(entryJSON),
	)
	if err != nil {
		return fmt.Errorf("sqlitefinder: insert entry: %w", err)
	}
	rowid, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("sqlitefinder: entry rowid: %w", err)
	}

	if err := insertSideValues(ctx, tx, "finder_entry_tags", rowid, pe.Entry.Tags); err != nil {
		return err
	}
	if err := insertSideValues(ctx, tx, "finder_entry_capabilities", rowid, pe.Entry.Capabilities); err != nil {
		return err
	}
	if err := insertSideValues(ctx, tx, "finder_entry_attestation_types", rowid, attestationTypes(pe.Entry)); err != nil {
		return err
	}
	return insertFTS(ctx, tx, rowid, pe.Entry)
}

// applyTombstone suppresses every ACTIVE row for the tombstone's ansName
// whose created_at is no newer than the tombstone's (an out-of-order
// replay of an old revoke must not bury a newer registration).
// Suppression flips lifecycle, blanks the searchable display fields,
// clears side-tables and the FTS row, and records the tombstone's
// log_id/created_at.
//
// It returns noOp=true when it suppressed ZERO rows while ACTIVE rows for
// the ansName still exist — the revoke landed but did nothing, most likely
// because a producer clock step-back made the revoke's created_at older
// than the registration it should suppress. That agent stays
// discoverable, so the caller must surface it.
func applyTombstone(ctx context.Context, tx *sqlx.Tx, pe project.ProjectedEntry) (bool, error) {
	rowids, err := suppressibleRowids(ctx, tx, pe.AnsName, pe.CreatedAt)
	if err != nil {
		return false, err
	}
	for _, rowid := range rowids {
		if err := clearSideAndFTS(ctx, tx, rowid); err != nil {
			return false, err
		}
	}
	res, err := tx.ExecContext(ctx, `
        UPDATE finder_entries
           SET lifecycle = ?, log_id = ?, created_at = ?,
               display_name = '', description = ''
         WHERE ans_name = ? AND lifecycle = 'ACTIVE' AND created_at <= ?`,
		string(pe.Lifecycle), pe.LogID, pe.CreatedAt, pe.AnsName, pe.CreatedAt,
	)
	if err != nil {
		return false, fmt.Errorf("sqlitefinder: apply tombstone: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("sqlitefinder: tombstone rows affected: %w", err)
	}
	if affected > 0 {
		return false, nil
	}
	// Suppressed nothing — flag it only if the agent is still active.
	stillActive, err := hasActiveRows(ctx, tx, pe.AnsName)
	if err != nil {
		return false, err
	}
	return stillActive, nil
}

// hasActiveRows reports whether any ACTIVE row remains for an ansName.
func hasActiveRows(ctx context.Context, tx *sqlx.Tx, ansName string) (bool, error) {
	var n int
	if err := tx.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM finder_entries WHERE ans_name = ? AND lifecycle = 'ACTIVE'`,
		ansName); err != nil {
		return false, fmt.Errorf("sqlitefinder: count active rows: %w", err)
	}
	return n > 0, nil
}

// suppressibleRowids lists the ACTIVE rows for an ansName that a tombstone
// with the given created_at would suppress, so their FTS and side-table
// rows can be cleared before the UPDATE rewrites them.
func suppressibleRowids(ctx context.Context, tx *sqlx.Tx, ansName, createdAt string) ([]int64, error) {
	return scanRowids(ctx, tx, `
        SELECT id FROM finder_entries
         WHERE ans_name = ? AND lifecycle = 'ACTIVE' AND created_at <= ?`,
		ansName, createdAt)
}

// rowidsForAnsName lists every row id for an ansName regardless of
// lifecycle (used by the Active replace path).
func rowidsForAnsName(ctx context.Context, tx *sqlx.Tx, ansName string) ([]int64, error) {
	return scanRowids(ctx, tx, `SELECT id FROM finder_entries WHERE ans_name = ?`, ansName)
}

// scanRowids runs a query selecting a single id column and collects the
// results.
func scanRowids(ctx context.Context, tx *sqlx.Tx, query string, args ...any) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlitefinder: select rowids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("sqlitefinder: scan rowid: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlitefinder: iterate rowids: %w", err)
	}
	return ids, nil
}

// clearSideAndFTS removes a row's FTS entry and its side-table rows
// without deleting the base row (used by tombstone suppression, which
// keeps the base row but blanks its searchable content, and by the
// delete-all path before the base rows are dropped).
func clearSideAndFTS(ctx context.Context, tx *sqlx.Tx, rowid int64) error {
	if err := deleteFTS(ctx, tx, rowid); err != nil {
		return err
	}
	for _, table := range []string{
		"finder_entry_tags",
		"finder_entry_capabilities",
		"finder_entry_attestation_types",
	} {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE entry_rowid = ?`, table), rowid); err != nil {
			return fmt.Errorf("sqlitefinder: clear %s: %w", table, err)
		}
	}
	return nil
}

// insertSideValues writes the normalized rows for one multi-valued field.
// Empty input is a no-op.
func insertSideValues(ctx context.Context, tx *sqlx.Tx, table string, rowid int64, values []string) error {
	for _, v := range values {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(`INSERT INTO %s (entry_rowid, value) VALUES (?, ?)`, table),
			rowid, v); err != nil {
			return fmt.Errorf("sqlitefinder: insert %s: %w", table, err)
		}
	}
	return nil
}

// insertFTS writes the FTS row for an entry, flattening capabilities and
// tags into space-joined text columns the tokenizer can index.
func insertFTS(ctx context.Context, tx *sqlx.Tx, rowid int64, e project.Entry) error {
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO finder_entries_fts (rowid, display_name, description, capabilities_text, tags_text)
        VALUES (?,?,?,?,?)`,
		rowid, e.DisplayName, e.Description,
		strings.Join(e.Capabilities, " "), strings.Join(e.Tags, " ")); err != nil {
		return fmt.Errorf("sqlitefinder: insert fts: %w", err)
	}
	return nil
}

// deleteFTS removes an entry's FTS row. A standalone (non-external-
// content) FTS5 table supports a plain row delete by rowid, so there is
// no need for the external-content 'delete' command protocol (which
// requires re-supplying the indexed column values and which modernc's
// FTS5 rejects). Deleting an absent rowid is a harmless no-op.
func deleteFTS(ctx context.Context, tx *sqlx.Tx, rowid int64) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM finder_entries_fts WHERE rowid = ?`, rowid); err != nil {
		return fmt.Errorf("sqlitefinder: delete fts: %w", err)
	}
	return nil
}

// attestationTypes collects the attestation type tokens from an entry's
// trust manifest for the attestation-type filter/facet dimension.
func attestationTypes(e project.Entry) []string {
	if e.TrustManifest == nil {
		return nil
	}
	out := make([]string, 0, len(e.TrustManifest.Attestations))
	for _, a := range e.TrustManifest.Attestations {
		if a.Type != "" {
			out = append(out, a.Type)
		}
	}
	return out
}

// publisherFromURN extracts the <publisher> segment from a Finder URN
// (urn:air:<publisher>:agents:<label>). It returns "" for any string that
// is not a Finder URN, which keeps a tombstone with no identifier (or a
// malformed one) from acquiring a spurious publisher.
func publisherFromURN(urn string) string {
	const prefix = "urn:air:"
	if !strings.HasPrefix(urn, prefix) {
		return ""
	}
	rest := urn[len(prefix):]
	idx := strings.IndexByte(rest, ':')
	if idx <= 0 {
		return ""
	}
	return rest[:idx]
}
