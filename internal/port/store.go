package port

import (
	"context"

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

// FeedRow is the raw, store-shaped projection of one delivered outbox
// row joined with its registration and endpoint rows. It is the read
// model behind the agent-events feed (GET /v1/agents/events). The
// service layer maps a FeedRow into the wire EventItem; the SQLite
// adapter populates it.
type FeedRow struct {
	// LogID is the TL-assigned cursor (outbox.log_id). Non-empty by
	// construction — the store filters log_id IS NOT NULL.
	LogID string
	// EventType is the outbox row's event_type column.
	EventType string
	// AgentID is the outbox row's agent_id column (the authoritative
	// id — owner_id is never exposed through the feed).
	AgentID string
	// PayloadJSON is the outbox payload blob ({innerEventCanonical,
	// producerSignature}); the inner event carries the producer's
	// authoritative timestamps and identity.
	PayloadJSON []byte
	// RegAnsName / RegAgentHost / RegVersion are the registration-row
	// identity columns, used as fallbacks when the inner event omits
	// them.
	RegAnsName   string
	RegAgentHost string
	RegVersion   string
	// RegDisplayName / RegDescription are the registration-row display
	// metadata columns.
	RegDisplayName string
	RegDescription string
	// EndpointsJSON is the agent_endpoints.endpoints blob, or empty
	// when the agent has no recorded endpoints.
	EndpointsJSON []byte
}

// FeedQuery parameterizes a feed read.
type FeedQuery struct {
	// AfterLogID is the resolved cursor — rows strictly after the row
	// carrying this logId are returned. Empty (or a cursor that
	// resolves to no retained row) starts from the oldest retained row.
	AfterLogID string
	// Limit is the maximum number of rows to return. The service clamps
	// it to the feed's [1, max] range before calling.
	Limit int
	// ProviderFilter, when non-empty, requests provider-scoped results.
	// The OSS RA has no provider concept, so the store returns an empty
	// page in that case.
	ProviderFilter string
}

// FeedReader is the read port behind the agent-events feed. The SQLite
// adapter implements it; the events service depends on it.
type FeedReader interface {
	// ReadFeed returns delivered, logged outbox rows within the
	// retention window, ordered by outbox id ascending, starting after
	// the cursor (or the oldest retained row when the cursor is empty
	// or unknown). It returns at most q.Limit rows.
	ReadFeed(ctx context.Context, q FeedQuery) ([]FeedRow, error)
}
