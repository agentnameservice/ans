package port

import "context"

// HTTPChallengeVerifier checks that the domain owner has published an
// HTTP-01 challenge artifact at the expected path under their FQDN.
// Like the DNSVerifier, it is verification-only: ANS never serves
// challenge files on the owner's behalf — the owner publishes the
// artifact themselves from the challenge info relayed in the pending
// response.
type HTTPChallengeVerifier interface {
	// VerifyHTTPChallenge fetches `http://<fqdn><path>` and reports
	// whether the response body matches the expected content (the key
	// authorization for account-bound challenges, the raw token
	// otherwise). Returns (false, nil) when the artifact is missing or
	// mismatched; a non-nil error indicates a systemic failure that
	// prevented checking at all (which callers treat the same as
	// not-published, since an unreachable host cannot prove control).
	VerifyHTTPChallenge(ctx context.Context, fqdn, path, expectedContent string) (bool, error)
}
