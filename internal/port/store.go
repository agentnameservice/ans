package port

import (
	"context"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// CursorPage is a generic cursor-paginated result set.
// NextCursor is opaque and should be passed unchanged as the Cursor
// field in the next ListFilter. An empty NextCursor combined with
// HasMore=false signals the end of the result set.
type CursorPage[T any] struct {
	Items         []T
	NextCursor    string
	HasMore       bool
	ReturnedCount int
}

// ListFilter controls cursor-paginated listing of agents owned by a caller.
type ListFilter struct {
	Statuses  []domain.RegistrationStatus // nil or empty means "all statuses"
	AgentHost string                      // exact match if non-empty
	Limit     int                         // 1-100; 0 means default (20)
	Cursor    string                      // opaque; empty for first page
}

// AgentStore persists AgentRegistration aggregates and supports all
// query patterns required by the V2 management and registration APIs.
type AgentStore interface {
	// Save inserts or updates an AgentRegistration. If agent.ID == 0 the
	// implementation must assign a new ID and set it on the aggregate.
	Save(ctx context.Context, agent *domain.AgentRegistration) error

	// FindByID returns the agent with the given database ID or
	// domain.ErrNotFound.
	FindByID(ctx context.Context, id int64) (*domain.AgentRegistration, error)

	// FindByAgentID returns the agent with the given stable agent UUID.
	FindByAgentID(ctx context.Context, agentID string) (*domain.AgentRegistration, error)

	// FindByAnsName returns the agent with the given versioned ANS name.
	FindByAnsName(ctx context.Context, ansName domain.AnsName) (*domain.AgentRegistration, error)

	// ExistsByAnsName returns true if any registration uses the given name.
	ExistsByAnsName(ctx context.Context, ansName domain.AnsName) (bool, error)

	// FindAllByAgentHost returns every registration (any version, any status)
	// for the given FQDN, newest first.
	FindAllByAgentHost(ctx context.Context, host string) ([]*domain.AgentRegistration, error)

	// FindExistingByFQDN returns ACTIVE or PENDING_* registrations for the
	// given FQDN, newest first. Used to check for supersession candidates.
	FindExistingByFQDN(ctx context.Context, fqdn string) ([]*domain.AgentRegistration, error)

	// ListByOwner returns a cursor page of agents owned by ownerID.
	ListByOwner(
		ctx context.Context,
		ownerID string,
		filter ListFilter,
	) (*CursorPage[*domain.AgentRegistration], error)

	// Delete removes the registration with the given ID. Used only for
	// administrative cleanup; normal lifecycle uses Revoke.
	Delete(ctx context.Context, id int64) error
}

// CertificateStore persists identity certificates and CSRs issued by the
// system's private CA. BYOC server certificates are handled by
// ByocCertificateStore.
type CertificateStore interface {
	// SaveIdentityCertificate persists a newly issued identity certificate.
	SaveIdentityCertificate(
		ctx context.Context,
		agentID string,
		cert *domain.StoredCertificate,
	) error

	// FindIdentityCertificatesByAgent returns all identity certificates
	// for the given agent, newest first.
	FindIdentityCertificatesByAgent(
		ctx context.Context,
		agentID string,
	) ([]*domain.StoredCertificate, error)

	// UpdateCertificateStatus updates the status of an existing certificate.
	UpdateCertificateStatus(
		ctx context.Context,
		cert *domain.StoredCertificate,
	) error

	// SaveCSR persists a new or updated CSR (identity or server).
	// Upserts on csr_id; status transitions replace the previous row.
	SaveCSR(
		ctx context.Context,
		agentID string,
		csr *domain.AgentCSR,
	) error

	// FindCSRByID returns the CSR with the given ID, scoped to the
	// given agent. Used by the CSR-status handler and the registration
	// flow's post-rotation refresh.
	FindCSRByID(
		ctx context.Context,
		agentID, csrID string,
	) (*domain.AgentCSR, error)

	// FindLatestPendingCSRByType returns the most recent PENDING CSR
	// of the given type (IDENTITY or SERVER) for an agent, or
	// (nil, nil) when none exists. Used by VerifyACME to pull the
	// CSRs submitted at register time for signing once domain
	// control has been proven.
	FindLatestPendingCSRByType(
		ctx context.Context,
		agentID string,
		csrType domain.CSRType,
	) (*domain.AgentCSR, error)
}

// EndpointStore persists AgentEndpoints collections.
type EndpointStore interface {
	Save(ctx context.Context, endpoints *domain.AgentEndpoints) error
	FindByAgentID(ctx context.Context, agentID string) (*domain.AgentEndpoints, error)
	FindByAgentIDs(ctx context.Context, agentIDs []string) (map[string]*domain.AgentEndpoints, error)
}

// RenewalStore persists server certificate renewal aggregates.
// At most one renewal per agent may exist in a non-terminal state.
type RenewalStore interface {
	Save(ctx context.Context, renewal *domain.ServerCertificateRenewal) error
	FindByAgentID(ctx context.Context, agentID string) (*domain.ServerCertificateRenewal, error)
	FindPendingByAgentID(ctx context.Context, agentID string) (*domain.ServerCertificateRenewal, error)
	Delete(ctx context.Context, id int64) error
	ListPendingExpired(ctx context.Context) ([]*domain.ServerCertificateRenewal, error)
}

// RevocationStore persists AgentRevocation audit records.
type RevocationStore interface {
	Save(ctx context.Context, revocation *domain.AgentRevocation) error
	FindByAgentID(ctx context.Context, agentID string) (*domain.AgentRevocation, error)
}

// ByocCertificateStore persists operator-provided server certificates.
// Unlike identity certs, BYOC certs are never issued by us — we only
// validate and store them.
type ByocCertificateStore interface {
	Save(ctx context.Context, agentID string, cert *domain.ByocServerCertificate) error
	FindByAgentID(ctx context.Context, agentID string) ([]*domain.ByocServerCertificate, error)
	FindLatestValidByAgentID(ctx context.Context, agentID string) (*domain.ByocServerCertificate, error)
}

// IdentityStore persists VerifiedIdentity aggregates (the "who" —
// owned by a providerId, independent of any agent).
type IdentityStore interface {
	// Save upserts the aggregate. The storage layer enforces the two
	// uniqueness rules with partial indexes: one live (non-REVOKED)
	// row per (provider, kind, value), and one VERIFIED row per
	// (kind, value) across all owners — first to prove wins; a save
	// that loses the race maps to a conflict error.
	Save(ctx context.Context, identity *domain.VerifiedIdentity) error

	// FindByID returns the identity with the given identityId.
	FindByID(ctx context.Context, identityID string) (*domain.VerifiedIdentity, error)

	// FindLive returns the owner's non-REVOKED row for (kind, value),
	// or a not-found error. Drives the idempotent re-add: a re-POST
	// of the same value while PENDING_CONTROL returns the same
	// identity with a fresh challenge.
	FindLive(ctx context.Context, providerID string, kind domain.IdentifierKind, value string) (*domain.VerifiedIdentity, error)

	// ExistsVerified reports whether ANY owner holds a VERIFIED row
	// for (kind, value) — early duplicate feedback at register time.
	// The authoritative guard is the proven-uniqueness index at
	// verify time.
	ExistsVerified(ctx context.Context, kind domain.IdentifierKind, value string) (bool, error)

	// ListByOwner returns every identity owned by the principal,
	// newest first.
	ListByOwner(ctx context.Context, providerID string) ([]*domain.VerifiedIdentity, error)

	// ConsumeChallenge atomically consumes the live challenge nonce:
	// a conditional update that succeeds only while the stored nonce
	// matches, is unconsumed, and is unexpired. Exactly one of two
	// concurrent verify-control calls can win (the TOCTOU guard);
	// the loser receives an invalid-state error. MUST be called
	// inside the verify-control success transaction.
	ConsumeChallenge(ctx context.Context, identityID, nonce string, now time.Time) error
}

// IdentityLinkStore persists identity↔agent link rows. Rows are
// read-side caches of the sealed IDENTITY_LINKED / IDENTITY_UNLINKED
// events; UNLINKED rows are history and never block re-linking.
type IdentityLinkStore interface {
	// Link upserts a live link for the pair. Returns true when a new
	// link was created, false when the pair was already live
	// (idempotent — an already-linked agent in a batch is not an
	// error, and is excluded from the sealed batch event).
	Link(ctx context.Context, identityID, agentID string, now time.Time) (bool, error)

	// Unlink flips the live link to UNLINKED. Not-found error when no
	// live link exists.
	Unlink(ctx context.Context, identityID, agentID string, now time.Time) error

	// ListLiveByIdentity returns the identity's live links.
	ListLiveByIdentity(ctx context.Context, identityID string) ([]*domain.IdentityLink, error)

	// ListLiveByAgent returns the agent's live links.
	ListLiveByAgent(ctx context.Context, agentID string) ([]*domain.IdentityLink, error)
}
