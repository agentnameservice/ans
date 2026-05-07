package port

import "context"

// UnitOfWork groups multiple store writes into a single atomic
// commit. Service-layer methods that touch more than one aggregate
// (or one aggregate plus the outbox) hand a closure to `Run`; the
// adapter manages begin / commit / rollback. The closure receives a
// scoped `context.Context` that downstream stores use to find the
// active transaction — callers should pass that scoped context to
// every store call inside the closure.
//
// Implementations must:
//
//   - Begin a transaction (or equivalent atomic batch) before
//     invoking fn.
//   - Roll back if fn returns a non-nil error and propagate that
//     error.
//   - Commit if fn returns nil; surface any commit error to the
//     caller.
//   - Be safe to call concurrently from multiple goroutines, each
//     with its own scoped ctx.
//
// SQL adapters back this with `BEGIN`/`COMMIT`/`ROLLBACK`. Cloud
// stores without true ACID transactions (DynamoDB, Spanner) can
// implement the same contract via TransactWriteItems / batched
// mutations as long as the all-or-nothing semantics hold.
type UnitOfWork interface {
	Run(ctx context.Context, fn func(ctx context.Context) error) error
}
