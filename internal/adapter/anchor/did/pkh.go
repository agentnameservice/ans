package did

// did:pkh resolution per the [W3C CCG did:pkh method specification]
// (https://github.com/w3c-ccg/did-pkh) and CAIP-10 account identifiers.
//
// did:pkh is the path the proposal at anchor-0b-did.md §6 names for
// ERC-8004 on-chain agent identity. The DID URI carries a CAIP-10
// account identifier (e.g., "eip155:1:0x...") that resolves to an
// on-chain controller address. The resolver's job is lexical
// validation + chain identifier parsing; the actual on-chain lookup
// (reading the ERC-8004 IdentityRegistry, decoding the controller's
// verification key) is delegated to a ChainResolver injected via
// WithChainResolver.
//
// This slice ships the lexical layer in full plus the ChainResolver
// interface; the production HTTP-RPC implementation against an
// Ethereum node lands when an actual ERC-8004 testnet deployment
// is wired into CI. The pattern mirrors the LEI resolver's
// GLEIFClient injection: the package is useful for unit tests and
// CAIP-10 validation today, and switches to live resolution by
// configuration without code changes.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// PkhProfileID is the canonical identifier for did:pkh in the
// AnchorResolverRegistry advertised through SupportedProfiles().
const PkhProfileID = "0.B-did:pkh"

// pkhFreshnessBudget bounds the cache lifetime for a did:pkh claim.
// 1 hour to match the FQDN profile and to keep on-chain state
// monitoring tight; verifiers MAY shorten further when a chain
// reorganization is observed.
const pkhFreshnessBudget = 1 * time.Hour

// CAIPAccount is the parsed form of a CAIP-10 account identifier
// per [CAIP-10] (https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-10.md).
//
// Fields:
//
//	Namespace   the chain-agnostic family (eip155, solana, cosmos, ...)
//	Reference   the network identifier within the namespace (chain ID
//	            for eip155, ledger hash prefix for solana, etc.)
//	Address     the account-level identifier on that network
//
// Example: did:pkh:eip155:1:0xa1b2... → CAIPAccount{Namespace:
// "eip155", Reference: "1", Address: "0xa1b2..."}.
type CAIPAccount struct {
	Namespace string
	Reference string
	Address   string
}

// String returns the canonical CAIP-10 form: <ns>:<ref>:<address>.
func (c CAIPAccount) String() string {
	return c.Namespace + ":" + c.Reference + ":" + c.Address
}

// ChainResolver abstracts the chain-specific lookup the did:pkh
// resolver needs to convert an account identifier to a verification
// key. Implementations live outside this package so the resolver
// does not link an Ethereum RPC client (or any other chain library)
// at compile time.
//
// The resolver passes a parsed CAIPAccount; the implementation
// returns the verification key in JWK form. ERC-8004 implementations
// MAY also return additional metadata (controller address change
// history, on-chain reputation snapshot) but the resolver only
// needs the JWK for the IdentityClaim.
type ChainResolver interface {
	// LookupKey returns the verification key for the given account.
	// Implementations MUST validate the account's controller is
	// active and reject revoked or transferred controllers per the
	// chain's semantics.
	LookupKey(ctx context.Context, account CAIPAccount) ([]byte, error)
}

// Pkh implements port.AnchorResolver for did:pkh anchors.
type Pkh struct {
	chain ChainResolver
	clock func() time.Time
}

// NewPkh constructs a Pkh resolver with no chain client. Lexical
// validation runs offline; full resolution returns
// DID_PKH_CHAIN_NOT_CONFIGURED until WithChainResolver is used.
// This keeps the resolver useful for testbeds without forcing every
// downstream environment to wire an Ethereum RPC endpoint.
func NewPkh() *Pkh {
	return &Pkh{clock: time.Now}
}

// WithChainResolver injects a chain client and returns a copy of
// the resolver. Different chains plug in through different
// ChainResolver implementations; a single resolver MAY route by
// CAIPAccount.Namespace internally.
func (p *Pkh) WithChainResolver(c ChainResolver) *Pkh {
	return &Pkh{chain: c, clock: p.clock}
}

// WithClock returns a copy with a deterministic clock for tests.
func (p *Pkh) WithClock(clock func() time.Time) *Pkh {
	return &Pkh{chain: p.chain, clock: clock}
}

// SupportedProfiles satisfies port.AnchorResolver.
func (p *Pkh) SupportedProfiles() []string {
	return []string{PkhProfileID}
}

// Resolve validates the input did:pkh URI and (when a ChainResolver
// is configured) fetches the verification key.
//
// Pipeline:
//  1. Lexical validation: did:pkh: prefix + CAIP-10 shape.
//  2. CAIP-10 parsing into namespace, reference, address.
//  3. Per-namespace address validation (eip155: 0x + 40 hex).
//  4. If no ChainResolver is configured: return
//     DID_PKH_CHAIN_NOT_CONFIGURED. This is the slice boundary; the
//     production client lands once the testnet wiring is in place.
//  5. ChainResolver.LookupKey -> JWK.
//  6. Construct IdentityClaim with ExpiresAt = now + 1h.
func (p *Pkh) Resolve(ctx context.Context, input string) (*domain.IdentityClaim, error) {
	account, err := parseDIDPkh(input)
	if err != nil {
		return nil, err
	}
	if err := validateAccountAddress(account); err != nil {
		return nil, err
	}
	canonical := canonicalizeDIDPkh(account)
	if p.chain == nil {
		return nil, domain.NewInternalError(
			"DID_PKH_CHAIN_NOT_CONFIGURED",
			"did:pkh resolver has no ChainResolver configured; lexical validation passed but full resolution requires WithChainResolver",
			nil,
		)
	}
	jwk, err := p.chain.LookupKey(ctx, account)
	if err != nil {
		return nil, domain.NewValidationError(
			"DID_PKH_CHAIN_LOOKUP_FAILED",
			"chain lookup failed: "+err.Error(),
		)
	}
	if len(jwk) == 0 {
		return nil, domain.NewValidationError(
			"DID_PKH_NO_KEY",
			"chain returned no key for "+canonical,
		)
	}
	now := p.clock().UTC()
	return &domain.IdentityClaim{
		AnchorType:   domain.AnchorTypeDID,
		ResolvedID:   canonical,
		PublicKeyJWK: jwk,
		IssuedAt:     now,
		ExpiresAt:    now.Add(pkhFreshnessBudget),
	}, nil
}

// parseDIDPkh splits did:pkh:<namespace>:<reference>:<address>
// into a CAIPAccount.
func parseDIDPkh(input string) (CAIPAccount, error) {
	trimmed := strings.TrimSpace(input)
	if !strings.HasPrefix(trimmed, "did:pkh:") {
		return CAIPAccount{}, domain.NewValidationError(
			"DID_BAD_FORMAT",
			"expected did:pkh prefix",
		)
	}
	rest := strings.TrimPrefix(trimmed, "did:pkh:")
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) != 3 {
		return CAIPAccount{}, domain.NewValidationError(
			"DID_PKH_BAD_FORMAT",
			"did:pkh body must be <namespace>:<reference>:<address>",
		)
	}
	ns := strings.ToLower(parts[0])
	ref := parts[1]
	addr := parts[2]
	if ns == "" || ref == "" || addr == "" {
		return CAIPAccount{}, domain.NewValidationError(
			"DID_PKH_BAD_FORMAT",
			"did:pkh body parts must all be non-empty",
		)
	}
	return CAIPAccount{Namespace: ns, Reference: ref, Address: addr}, nil
}

// canonicalizeDIDPkh reconstructs the canonical lowercase did:pkh
// URI for the IdentityClaim's ResolvedID. The namespace is lowercased
// per CAIP-2; the address case is namespace-specific (eip155
// preserves the EIP-55 checksum form when supplied; lowercase
// otherwise).
func canonicalizeDIDPkh(a CAIPAccount) string {
	addr := a.Address
	if a.Namespace == "eip155" {
		// EIP-55 checksum addresses are mixed-case; preserve as-is.
		// Pure-lowercase addresses are also valid; preserve those too.
		// A future implementation MAY enforce checksum validity here
		// (rejecting mixed-case addresses whose checksum does not
		// validate); today we admit both shapes.
		_ = addr
	}
	return "did:pkh:" + a.Namespace + ":" + a.Reference + ":" + addr
}

// validateAccountAddress applies per-namespace address-shape rules.
// Namespaces beyond eip155 admit any non-empty address at this slice;
// add per-namespace validators here as profiles expand.
func validateAccountAddress(a CAIPAccount) error {
	switch a.Namespace {
	case "eip155":
		return validateEIP155Address(a.Address)
	default:
		// Unknown namespace: accept the lexical shape; the chain
		// resolver implementation owns the per-chain rules.
		return nil
	}
}

// validateEIP155Address checks the Ethereum address shape:
// "0x" prefix + 40 hex characters (case-insensitive).
func validateEIP155Address(addr string) error {
	if !strings.HasPrefix(addr, "0x") && !strings.HasPrefix(addr, "0X") {
		return domain.NewValidationError(
			"DID_PKH_BAD_ADDRESS",
			fmt.Sprintf("eip155 address must start with 0x, got %q", addr),
		)
	}
	body := addr[2:]
	if len(body) != 40 {
		return domain.NewValidationError(
			"DID_PKH_BAD_ADDRESS",
			fmt.Sprintf("eip155 address body must be 40 hex chars, got %d", len(body)),
		)
	}
	for i, c := range body {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return domain.NewValidationError(
				"DID_PKH_BAD_ADDRESS",
				fmt.Sprintf("eip155 address body must be hex, got %q at position %d", c, i),
			)
		}
	}
	return nil
}
