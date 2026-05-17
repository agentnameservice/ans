// Package port also defines the Witness contract: a backend that
// produces an external attestation over a TL checkpoint, anchoring
// the log's state in a system outside the TL's own trust domain.
//
// Witness profiles (ANS_SPEC.md §4.11 + the layered-spec proposal's
// 4.A-4.D) are pluggable: a deployment may run zero, one, or several
// witnesses against the same TL state. The Witness interface here
// is the contract every profile implementation satisfies; concrete
// implementations live under internal/adapter/witness/<profile>/.
//
// Reference profiles:
//   - 4.A Hedera Consensus Service — HCS-27 Merkle profile. Lives
//     in the production TL deployment outside this repo.
//   - 4.C OpenTimestamps — Bitcoin-anchored timestamps via the public
//     calendar (ans-godaddy-ref ships this; see
//     internal/adapter/witness/opentimestamps).
//
// The Witness interface deliberately stays narrow: a checkpoint goes
// in, a backend-specific external proof comes out. Verification
// procedures for each profile are out-of-band — for OpenTimestamps,
// verify the returned .ots bytes against a Bitcoin SPV node or the
// off-the-shelf ots CLI; for Hedera, verify the topic-message
// receipt against the Hedera consensus state.
package port

import "context"

// WitnessAttestation is the result of a witness binding a TL
// checkpoint to an external system. The shape is intentionally
// backend-agnostic; backends use ExternalProof to carry whatever
// bytes their verifier needs (a Hedera receipt, an OTS proof file,
// a Bitcoin SPV proof, etc.).
//
// JSON-serializable so verifiers can roundtrip an attestation
// through a TL audit endpoint without losing fidelity.
type WitnessAttestation struct {
	// Profile identifies the witness backend (e.g., "4.A-hedera",
	// "4.C-opentimestamps"). Verifiers select the matching profile
	// implementation to validate ExternalProof.
	Profile string `json:"profile"`

	// CheckpointDigest is the SHA-256 of the canonical TL checkpoint
	// bytes the witness attested to. Verifiers MUST recompute this
	// from the live checkpoint and compare; mismatch means the
	// attestation refers to a different log state.
	CheckpointDigest []byte `json:"checkpointDigest"`

	// AttestedAt is when the witness produced the attestation.
	// RFC 3339 string for easy JSON; backends populate from their
	// own timestamp source (the calendar's response, the consensus
	// timestamp, etc.).
	AttestedAt string `json:"attestedAt"`

	// ExternalProof is the backend-specific evidence a verifier
	// runs through the matching profile's verification procedure.
	// For OpenTimestamps: the .ots binary. For Hedera: the encoded
	// HCS receipt. For Bitcoin direct: the SPV proof bytes.
	ExternalProof []byte `json:"externalProof"`
}

// Witness binds a TL checkpoint to an external trust system.
type Witness interface {
	// Profile returns the witness profile identifier (e.g.,
	// "4.C-opentimestamps"). Stable across calls; used by
	// verifiers to select the correct verification procedure.
	Profile() string

	// Attest produces an external attestation over the given
	// checkpoint bytes. The backend is responsible for hashing,
	// formatting, and submitting; the returned ExternalProof must
	// be sufficient input to the matching profile's verifier.
	//
	// Returning a non-nil error signals the attestation could not
	// be produced (calendar unreachable, consensus timeout, etc.).
	// Callers SHOULD retry on transient errors and SHOULD NOT
	// retry indefinitely on persistent ones.
	Attest(ctx context.Context, checkpoint []byte) (*WitnessAttestation, error)
}
