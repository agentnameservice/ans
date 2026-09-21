package service_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
)

type lostActivationAcknowledgement struct {
	bodies     [][]byte
	signatures []string
}

func (s *lostActivationAcknowledgement) SealAgentEvent(_ context.Context, _ string, body []byte, signature string) (string, error) {
	s.bodies = append(s.bodies, append([]byte(nil), body...))
	s.signatures = append(s.signatures, signature)
	if len(s.bodies) == 1 {
		return "", errors.New("acknowledgement lost after TL append")
	}
	return "original-log-id", nil
}

func TestActivationRetryReplaysPreparedSignatureAndBytes(t *testing.T) {
	fx := newRegFixture(t)
	sealer := &lostActivationAcknowledgement{}
	now := time.Now()
	svc := fx.svc.WithAgentSealer(sealer).WithClock(func() time.Time { return now })
	if _, err := svc.RegisterAgent(t.Context(), fx.req); err != nil {
		t.Fatal(err)
	}
	id := anyAgentID(t, fx, fx.req.AnsName)
	if _, err := svc.VerifyACME(t.Context(), id, service.VerifyInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyDNS(t.Context(), id, service.VerifyInput{}); err == nil {
		t.Fatal("lost acknowledgement activated agent")
	}
	reg, err := fx.agents.FindByAgentID(t.Context(), id)
	if err != nil || reg.Status != domain.StatusPendingDNS {
		t.Fatalf("activation did not remain pending: %v %v", reg, err)
	}
	now = now.Add(time.Minute)
	if _, err := svc.VerifyDNS(t.Context(), id, service.VerifyInput{}); err != nil {
		t.Fatal(err)
	}
	if len(sealer.bodies) != 2 || !bytes.Equal(sealer.bodies[0], sealer.bodies[1]) || sealer.signatures[0] != sealer.signatures[1] {
		t.Fatal("activation retry regenerated signed evidence")
	}
}
