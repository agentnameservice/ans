package outbox

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
	"github.com/agentnameservice/ans/internal/adapter/tlclient"
	"github.com/agentnameservice/ans/internal/ra/service"
	"github.com/rs/zerolog"
)

type rejectedSender struct{}

func (rejectedSender) Append(context.Context, string, []byte, string) (*tlclient.AppendResult, error) {
	return nil, &tlclient.PermanentError{Status: 422, Message: "rejected"}
}

func TestPermanentDeliveryBudgetProtectsRevocation(t *testing.T) {
	for _, kind := range []string{"AGENT_RENEWED", "AGENT_REVOKED"} {
		t.Run(kind, func(t *testing.T) {
			db, err := sqlite.Open(t.Context(), ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			store := sqlite.NewOutboxStore(db)
			payload, err := json.Marshal(service.OutboxPayload{InnerEventCanonical: json.RawMessage(`{"immutable":true}`), ProducerSignature: "original-signature"})
			if err != nil {
				t.Fatal(err)
			}
			id, err := store.Enqueue(t.Context(), kind, "agent", "V2", payload, time.Now().Add(-time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			worker := NewWorker(store, rejectedSender{}, zerolog.Nop(), Options{})
			for range 8 {
				worker.tick(t.Context())
				if _, err := db.DBX().Exec(`UPDATE outbox_events SET next_attempt_at_ms = 0 WHERE id = ?`, id); err != nil {
					t.Fatal(err)
				}
			}
			backlog, err := store.Backlog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var attempts int
			if err := db.DBX().Get(&attempts, `SELECT attempts FROM outbox_events WHERE id = ?`, id); err != nil {
				t.Fatal(err)
			}
			if kind == "AGENT_REVOKED" {
				if backlog.Pending != 1 || backlog.Dead != 0 || attempts != 8 {
					t.Fatalf("revocation abandoned: %+v, attempts=%d", backlog, attempts)
				}
			} else if backlog.Pending != 0 || backlog.Dead != 1 || attempts != 5 {
				t.Fatalf("modification budget: %+v, attempts=%d", backlog, attempts)
			}
		})
	}
}
