package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/tl/service"
)

// DTO + helpers for the checkpoint routes live in their own file to
// keep handler.go focused on route definitions.

// checkpointJSON mirrors the reference TL's CheckpointResponse
// byte-for-byte on the wire. Field order follows the production
// emit (alphabetical by JSON key) so the rendered JSON matches
// what clients observe from transparency.ans.godaddy.com.
// `createdAt` is an ans-specific additive field for operator
// debugging; reference clients ignore unknown JSON fields.
type checkpointJSON struct {
	CheckpointFormat string                   `json:"checkpointFormat"`
	CheckpointText   string                   `json:"checkpointText"`
	CreatedAt        string                   `json:"createdAt"`
	LogSize          uint64                   `json:"logSize"`
	OriginName       string                   `json:"originName"`
	PublicKeyPem     string                   `json:"publicKeyPem,omitempty"`
	RootHash         string                   `json:"rootHash"`
	Signatures       []checkpointSignatureDTO `json:"signatures"`
	TreeHeight       int                      `json:"treeHeight"`
}

// checkpointSignatureDTO matches the reference TL's CheckpointSignature
// byte-for-byte on the wire. Field order is alphabetical by JSON
// key — the production emit uses that ordering, so matching it gives
// a byte-stable response shape across TL implementations. Fields
// marked "JWS signatures only" in the reference are emitted with
// `omitempty` so they drop out on c2sp entries.
type checkpointSignatureDTO struct {
	Algorithm     string      `json:"algorithm"`
	JwsHeader     interface{} `json:"jwsHeader,omitempty"`
	JwsPayload    interface{} `json:"jwsPayload,omitempty"`
	JwsSignature  string      `json:"jwsSignature,omitempty"`
	KeyHash       string      `json:"keyHash"`
	KmsKeyID      string      `json:"kmsKeyId,omitempty"`
	RawSignature  string      `json:"rawSignature"`
	SignatureType string      `json:"signatureType"`
	SignerName    string      `json:"signerName"`
	Timestamp     string      `json:"timestamp,omitempty"`
	Valid         bool        `json:"valid,omitempty"`
}

type checkpointHistoryJSON struct {
	Checkpoints []checkpointJSON        `json:"checkpoints"`
	Pagination  checkpointPaginationDTO `json:"pagination"`
}

type checkpointPaginationDTO struct {
	Total      int64 `json:"total"`
	NextOffset *int  `json:"nextOffset,omitempty"`
}

// mapCheckpoint turns a service-layer CheckpointView into the JSON
// shape we return on the wire. Matches the reference TL's
// CheckpointResponse field-by-field.
func mapCheckpoint(cv *service.CheckpointView) checkpointJSON {
	sigs := make([]checkpointSignatureDTO, 0, len(cv.Signatures))
	for _, s := range cv.Signatures {
		dto := checkpointSignatureDTO{
			SignerName:    s.SignerName,
			SignatureType: s.SignatureType,
			Algorithm:     s.Algorithm,
			KeyHash:       s.KeyHash,
			RawSignature:  s.RawSignature,
			JwsHeader:     s.JwsHeader,
			JwsPayload:    s.JwsPayload,
			JwsSignature:  s.JwsSignature,
			KmsKeyID:      s.KmsKeyID,
			Valid:         s.Valid,
		}
		if !s.Timestamp.IsZero() {
			// Production emits 6-digit microseconds + `Z`, e.g.
			// "2026-04-23T20:19:44.000000Z". Match the format exactly.
			dto.Timestamp = s.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z")
		}
		sigs = append(sigs, dto)
	}
	return checkpointJSON{
		LogSize:          cv.LogSize,
		TreeHeight:       cv.TreeHeight,
		RootHash:         cv.RootHashBase64,
		OriginName:       cv.OriginName,
		CheckpointFormat: cv.CheckpointFormat,
		CheckpointText:   cv.CheckpointText,
		PublicKeyPem:     cv.PublicKeyPEM,
		CreatedAt:        cv.CreatedAt.UTC().Format(time.RFC3339),
		Signatures:       sigs,
	}
}

// mapCheckpointHistory turns a paginated service result into the
// reference's CheckpointHistoryResponse shape (§1335).
func mapCheckpointHistory(page *service.CheckpointPage) checkpointHistoryJSON {
	items := make([]checkpointJSON, 0, len(page.Items))
	for _, cv := range page.Items {
		items = append(items, mapCheckpoint(cv))
	}
	return checkpointHistoryJSON{
		Checkpoints: items,
		Pagination: checkpointPaginationDTO{
			Total:      page.Total,
			NextOffset: page.NextOffset,
		},
	}
}

// parseHistoryInput translates the URL query parameters into a
// service.HistoryInput, returning a validation error for malformed
// values. The reference swagger defines defaults (limit=10, offset=0,
// order=DESC) which we apply inside the service so a zero-valued
// input still behaves correctly.
func parseHistoryInput(r *http.Request) (*service.HistoryInput, error) {
	in := &service.HistoryInput{}
	q := r.URL.Query()

	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			return nil, domain.NewValidationError("INVALID_PARAMETERS",
				"limit must be between 1 and 100")
		}
		in.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, domain.NewValidationError("INVALID_PARAMETERS",
				"offset must be ≥ 0")
		}
		in.Offset = n
	}
	if v := q.Get("fromSize"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n < 1 {
			return nil, domain.NewValidationError("INVALID_PARAMETERS",
				"fromSize must be ≥ 1")
		}
		in.FromSize = &n
	}
	if v := q.Get("toSize"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n < 1 {
			return nil, domain.NewValidationError("INVALID_PARAMETERS",
				"toSize must be ≥ 1")
		}
		in.ToSize = &n
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, domain.NewValidationError("INVALID_PARAMETERS",
				"since must be RFC3339")
		}
		in.Since = &t
	}
	if v := q.Get("order"); v != "" {
		if v != "ASC" && v != "DESC" {
			return nil, domain.NewValidationError("INVALID_PARAMETERS",
				"order must be ASC or DESC")
		}
		in.Order = v
	}
	return in, nil
}
