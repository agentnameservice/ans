package logstore

import "golang.org/x/mod/sumdb/note"

// Option configures a logstore.Open call. Options compose — call them
// in any order; Open applies them left-to-right into a single options
// struct before constructing the Tessera appender.
type Option func(*options)

type options struct {
	additionalSigners []note.Signer
}

// WithAdditionalSigner registers an extra `note.Signer` Tessera will
// append to every published checkpoint. Use this to add a JWS
// signature line alongside the primary ed25519 sumdb-note signer —
// the output checkpoint has one `— <origin> <base64-sig>` line per
// signer, matching what the reference TL emits and what every
// tlog-tiles-compliant verifier expects.
//
// Multiple WithAdditionalSigner calls compose; each signer is
// appended in call order.
func WithAdditionalSigner(s note.Signer) Option {
	return func(o *options) {
		o.additionalSigners = append(o.additionalSigners, s)
	}
}
