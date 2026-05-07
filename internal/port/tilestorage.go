package port

import "context"

// TileStorage persists RFC 9162 Merkle tree tiles for the Transparency Log.
// A tile is a fixed-size slice of the Merkle tree at a given level and index;
// together they let clients reconstruct inclusion and consistency proofs.
//
// Addressing follows the Tessera convention:
//   - level 0 is the leaf layer
//   - level N each covers 2^8 nodes at level N-1
//   - index is the sequential tile number within its level
//
// Implementations must be safe for concurrent reads; writes are serialized
// by the Tessera driver and need not be concurrency-safe at this layer.
type TileStorage interface {
	// WriteTile persists the tile bytes at (level, index), overwriting any
	// existing tile at the same address. Data is opaque to this layer.
	WriteTile(ctx context.Context, level, index uint64, data []byte) error

	// ReadTile returns the tile bytes at (level, index). A missing tile
	// must return domain.ErrNotFound so callers can distinguish
	// "gap in the tree" from "storage broken".
	ReadTile(ctx context.Context, level, index uint64) ([]byte, error)
}
