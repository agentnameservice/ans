package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// The `_ans-badge.<fqdn>` TXT record is the one DNS record this binary
// reads. It is the record the RA provisions for every ANS-family style
// (internal/adapter/discovery/ans.BadgeRecord) and it carries the log
// that holds the registration:
//
//	_ans-badge.agent.example.com. IN TXT
//	  "v=ans-badge1; version=v1; url=https://tl.example.com/v1/agents/<agentId>"
//
// Resolving it turns an FQDN into the agentId the existing receipt and
// proof flow already takes. Nothing else about verification changes: the
// badge locates a registration, it is not evidence about one. There is no
// SVCB lookup here, no agent-card fetch, and no outcome for a name that
// is reachable but not registered.
const (
	// badgeOwnerPrefix is prepended to the FQDN to form the owner name
	// of the badge record.
	badgeOwnerPrefix = "_ans-badge."

	// badgeVersionTag is the v= value every ans-badge record carries.
	// A TXT record at the owner name without it is not a badge and is
	// ignored, so an operator may park unrelated TXT data there.
	badgeVersionTag = "ans-badge1"

	// badgeAgentsPath is the path segment the badge url= ends with. The
	// agentId is whatever follows it.
	badgeAgentsPath = "/v1/agents/"

	// defaultResolverPort is appended to a -dns value given as a bare
	// host or address.
	defaultResolverPort = "53"
)

// badge is one parsed `_ans-badge` TXT record: the log that holds the
// registration, and the agent it is filed under.
type badge struct {
	// Owner is the name that was queried, kept for error and log lines.
	Owner string
	// AgentID is the UUID read out of the url= path.
	AgentID string
	// TLBaseURL is url= with the /v1/agents/<agentId> suffix removed,
	// so it can be joined with the paths the verifier already fetches.
	TLBaseURL string
	// Version is the version= value (the v-prefixed ANSName version
	// segment, e.g. "v1"). Empty when the record omits it.
	Version string
	// Raw is the record as served, for the printed audit line.
	Raw string
}

// txtLookupFunc resolves the TXT records at a name. Injected so the
// badge logic is exercised without a resolver.
type txtLookupFunc func(ctx context.Context, name string) ([]string, error)

// newTXTLookup returns a lookup backed by the Go resolver. An empty
// server uses the system configuration; a "host:port" (or bare host,
// which takes port 53) targets that resolver directly, which is how the
// local `ans-dns` dev server is reached.
func newTXTLookup(server string, timeout time.Duration) txtLookupFunc {
	addr := normalizeResolverAddr(server)
	if addr == "" {
		return net.DefaultResolver.LookupTXT
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, addr)
		},
	}
	return func(ctx context.Context, name string) ([]string, error) {
		txts, err := resolver.LookupTXT(ctx, name)
		if err != nil {
			// The Go resolver names the server from the system
			// configuration in its error even when Dial sent the query
			// somewhere else, which reads as though -dns was ignored.
			// Say which resolver actually answered.
			return nil, fmt.Errorf("via %s: %w", addr, err)
		}
		return txts, nil
	}
}

// normalizeResolverAddr gives a bare host or IP the default DNS port.
// An empty input stays empty, meaning "use the system resolver".
func normalizeResolverAddr(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		return net.JoinHostPort(server, defaultResolverPort)
	}
	return server
}

// resolveBadge looks up `_ans-badge.<fqdn>` and returns the single ANS
// badge published there.
//
// Every failure is an error, and every error is fatal to the caller: a
// name with no resolvable badge has no ANS registration this tool can
// locate, and falling back to anything else would be the non-ANS
// verification path this command does not have.
func resolveBadge(ctx context.Context, lookup txtLookupFunc, fqdn string) (badge, error) {
	name := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	if name == "" {
		return badge{}, errors.New("empty FQDN")
	}
	owner := badgeOwnerPrefix + name
	txts, err := lookup(ctx, owner)
	if err != nil {
		return badge{}, fmt.Errorf("lookup TXT %s: %w", owner, err)
	}

	var found []badge
	var malformed []string
	for _, txt := range txts {
		b, err := parseBadgeTXT(txt)
		switch {
		case err == nil:
			b.Owner = owner
			found = append(found, b)
		case looksLikeBadge(txt):
			malformed = append(malformed, err.Error())
		}
	}

	switch {
	case len(found) == 0 && len(malformed) > 0:
		return badge{}, fmt.Errorf("malformed badge record at %s: %s",
			owner, strings.Join(malformed, "; "))
	case len(found) == 0:
		return badge{}, fmt.Errorf(
			"no %q TXT record at %s (%d TXT record(s) present)",
			"v="+badgeVersionTag, owner, len(txts))
	}

	if distinct := distinctBadges(found); len(distinct) > 1 {
		return badge{}, fmt.Errorf(
			"%s publishes %d different badges (%s): which registration to verify is ambiguous",
			owner, len(distinct), strings.Join(distinct, ", "))
	}
	return found[0], nil
}

// distinctBadges returns the sorted set of "<baseURL> <agentId>" pairs
// across the badges found at one name. More than one means the name
// names more than one registration, which this tool will not choose
// between.
func distinctBadges(badges []badge) []string {
	out := make([]string, 0, len(badges))
	for _, b := range badges {
		key := b.TLBaseURL + badgeAgentsPath + b.AgentID
		if !slices.Contains(out, key) {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

// looksLikeBadge reports whether a TXT record claims to be an ans-badge
// record. Used to tell a malformed badge, which is an error worth
// reporting, from unrelated TXT data at the same name, which is not.
func looksLikeBadge(txt string) bool {
	return strings.Contains(strings.ToLower(txt), "v="+badgeVersionTag)
}

// parseBadgeTXT parses the `k=v; k=v` presentation of a badge record.
// Keys are taken first-wins, matching how the RA writes exactly one of
// each. An unparseable or non-badge record is an error, never a partial
// result.
func parseBadgeTXT(txt string) (badge, error) {
	fields := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		if _, seen := fields[key]; !seen {
			fields[key] = strings.TrimSpace(part[eq+1:])
		}
	}
	if !strings.EqualFold(fields["v"], badgeVersionTag) {
		return badge{}, fmt.Errorf("v=%q is not %q", fields["v"], badgeVersionTag)
	}
	raw := fields["url"]
	if raw == "" {
		return badge{}, errors.New("badge record carries no url=")
	}
	baseURL, agentID, err := splitBadgeURL(raw)
	if err != nil {
		return badge{}, err
	}
	return badge{
		AgentID:   agentID,
		TLBaseURL: baseURL,
		Version:   fields["version"],
		Raw:       strings.TrimSpace(txt),
	}, nil
}

// splitBadgeURL splits a badge url= into the log's base URL and the
// agentId it addresses. The url= the RA writes is
// `<tlPublicBaseURL>/v1/agents/<agentId>`; anything else is rejected
// rather than guessed at, including the endpoint URL BadgeRecord falls
// back to when the deployment has no TL base URL configured. Such a
// record does publish a reachable agent, and this command has no
// verdict for that: with no log named, there is no ANS evidence to
// check.
//
// The agentId must match the UUID shape the RA issues, for the same
// reason the tile walker checks it: it is interpolated into the paths
// this binary then fetches.
func splitBadgeURL(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("url=%q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("url=%q: scheme %q is not http or https", raw, u.Scheme)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("url=%q has no host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", fmt.Errorf("url=%q carries a query, fragment or userinfo", raw)
	}
	path := strings.TrimRight(u.Path, "/")
	cut := strings.LastIndex(path, badgeAgentsPath)
	if cut < 0 {
		return "", "", fmt.Errorf("url=%q is not a %s<agentId> path", raw, badgeAgentsPath)
	}
	agentID := path[cut+len(badgeAgentsPath):]
	if !agentIDPattern.MatchString(agentID) {
		return "", "", fmt.Errorf("url=%q: %q is not a UUID agentId", raw, agentID)
	}
	base := *u
	base.Path = path[:cut]
	return strings.TrimRight(base.String(), "/"), agentID, nil
}

// sameBaseURL compares two log base URLs for the agree/disagree line the
// FQDN step prints. A trailing slash and the case of scheme and host are
// not differences.
func sameBaseURL(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(b, "/"))
}

// badgeStepInput is what the FQDN entry point needs from the flags.
type badgeStepInput struct {
	FQDN          string
	Resolver      string
	Timeout       time.Duration
	ConfiguredURL string
	// URLExplicit is whether -url was passed rather than defaulted. It
	// decides whether the badge's log is adopted; see badgeStep.
	URLExplicit bool
	// Lookup overrides the resolver. Nil means "build one from
	// Resolver and Timeout", which is what the CLI passes.
	Lookup txtLookupFunc
	// Out receives the step's report. Nil means os.Stdout.
	Out io.Writer
}

// badgeStep resolves the FQDN's badge and returns the agentId to verify
// and the log base URL to verify it against. Any failure to resolve is
// fatal: the command verifies ANS registrations, so a name whose
// registration cannot be located has no other path through this tool.
//
// On the log: the badge is published by the same operator as the agent,
// so a name that chose its own log has not proved anything by saying so.
// An explicit -url therefore wins, and a badge that disagrees with it is
// reported rather than followed. The badge's log is adopted only when
// -url was left at its default, which is the case where the operator
// expressed no preference and the localhost default would be useless.
// Either way the evidence checked afterwards is unchanged.
func badgeStep(ctx context.Context, in badgeStepInput) (string, string) {
	lookupCtx, cancel := context.WithTimeout(ctx, in.Timeout)
	defer cancel()

	lookup := in.Lookup
	if lookup == nil {
		lookup = newTXTLookup(in.Resolver, in.Timeout)
	}
	out := in.Out
	if out == nil {
		out = os.Stdout
	}

	b, err := resolveBadge(lookupCtx, lookup, in.FQDN)
	if err != nil {
		fatalf("resolve ANS badge for %s: %v", in.FQDN, err)
	}

	fmt.Fprintln(out, "── Step 0: Resolve ANS badge ──")
	fmt.Fprintf(out, "  ✓ %s TXT: %s\n", b.Owner, b.Raw)
	if b.Version != "" {
		fmt.Fprintf(out, "    version: %s\n", b.Version)
	}

	baseURL := b.TLBaseURL
	switch {
	case !in.URLExplicit:
		fmt.Fprintf(out, "    log:     %s (named by the badge; -url not set)\n", baseURL)
	case sameBaseURL(in.ConfiguredURL, b.TLBaseURL):
		baseURL = in.ConfiguredURL
		fmt.Fprintf(out, "    log:     %s (badge names the same log)\n", baseURL)
	default:
		baseURL = in.ConfiguredURL
		fmt.Fprintf(out, "  ⚠ badge names %s; verifying against -url %s instead\n",
			b.TLBaseURL, in.ConfiguredURL)
	}
	fmt.Fprintln(out)
	return b.AgentID, strings.TrimRight(baseURL, "/")
}

// flagWasSet reports whether a flag was given on the command line, as
// opposed to holding its default. Visit walks only the flags that were
// actually set.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
