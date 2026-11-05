package scripts_test

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestCoverageGate(t *testing.T) {
	// Statement counts, rather than block counts, determine each percentage.
	// This profile sits exactly on both permitted lower bounds.
	boundary := coverageProfile(1, 0, 19, 1, 70, 9)
	for _, tc := range []struct {
		name    string
		profile string
		pass    bool
	}{
		{"threshold-boundaries", boundary, true},
		{"overall-below-minimum", coverageProfile(1, 0, 19, 1, 69, 10), false},
		{"domain-must-be-complete", coverageProfile(9, 1, 19, 1, 1000, 0), false},
		{"crypto-below-minimum", coverageProfile(1, 0, 18, 2, 1000, 0), false},
		{"missing-domain", coverageProfile(0, 0, 19, 1, 1000, 0), false},
		{"missing-crypto", coverageProfile(1, 0, 0, 0, 1000, 0), false},
		{"empty-profile", "mode: atomic\n", false},
		{"cmd-excluded", boundary + "example/cmd/server/main.go:1.1,1.2 10000 0\n", true},
		{"scripts-excluded", boundary + "example/scripts/demo/main.go:1.1,1.2 10000 0\n", true},
		// Repeated cross-package coverage blocks are counted once. An
		// uncovered observation must not erase another test's covered hit.
		{"duplicate-block-union", boundary +
			"example/internal/domain/source.go:1.1,1.2 1 0\n" +
			"example/internal/crypto/source.go:1.1,1.2 19 0\n" +
			"example/internal/service/source.go:2.1,2.2 9 0\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "awk", "-v", "minimum=90", "-f", "check-coverage.awk")
			cmd.Stdin = strings.NewReader(tc.profile)
			output, err := cmd.CombinedOutput()
			if tc.pass {
				if err != nil || !strings.Contains(string(output), "Coverage thresholds passed.") {
					t.Fatalf("valid coverage rejected: %v\n%s", err, output)
				}
				if !strings.Contains(string(output), "internal 90.00%, domain 100.00%, crypto 95.00%") {
					t.Fatalf("statement counts or exclusions changed: %s", output)
				}
				return
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(string(output), "FAIL:") {
				t.Fatalf("invalid coverage must fail the build: %v\n%s", err, output)
			}
		})
	}
}

func coverageProfile(domainCovered, domainMissed, cryptoCovered, cryptoMissed, otherCovered, otherMissed int) string {
	var profile strings.Builder
	profile.WriteString("mode: atomic\n")
	for _, group := range []struct {
		name    string
		covered int
		missed  int
	}{
		{"domain", domainCovered, domainMissed},
		{"crypto", cryptoCovered, cryptoMissed},
		{"service", otherCovered, otherMissed},
	} {
		if group.covered > 0 {
			fmt.Fprintf(&profile, "example/internal/%s/source.go:1.1,1.2 %d 1\n", group.name, group.covered)
		}
		if group.missed > 0 {
			fmt.Fprintf(&profile, "example/internal/%s/source.go:2.1,2.2 %d 0\n", group.name, group.missed)
		}
	}
	return profile.String()
}

func TestCoverageGateRejectsInvalidMinimum(t *testing.T) {
	for _, value := range []string{"", "invalid", "0", "-1", "101"} {
		t.Run("value="+value, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "awk", "-v", "minimum="+value, "-f", "check-coverage.awk")
			cmd.Stdin = strings.NewReader(coverageProfile(1, 0, 19, 1, 70, 9))
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "FAIL: minimum") {
				t.Fatalf("invalid threshold accepted: %v %s", err, output)
			}
		})
	}
	cmd := exec.CommandContext(t.Context(), "awk", "-f", "check-coverage.awk")
	cmd.Stdin = strings.NewReader(coverageProfile(1, 0, 19, 1, 70, 9))
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "FAIL: minimum") {
		t.Fatalf("missing threshold accepted: %v %s", err, output)
	}
}
