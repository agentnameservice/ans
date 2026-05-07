package receipt

// White-box tests for the small CBOR-numeric coercion helpers in
// verify.go. The fxamacker/cbor decoder normalizes most numerics to
// int64 / uint64 — but the broad switches in toInt/toUint64 cover
// the full set of Go integer types so a future cbor library swap
// (or a verifier called from non-cbor code) doesn't silently drop
// values. Direct unit tests pin every arm.

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// ----- toInt -----

func TestToInt_AllNumericTypes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int
	}{
		{"int", int(7), 7},
		{"int64", int64(8), 8},
		{"uint64", uint64(9), 9},
		{"int32", int32(10), 10},
		{"uint32", uint32(11), 11},
		{"int8", int8(12), 12},
		{"uint8", uint8(13), 13},
		{"int16", int16(14), 14},
		{"uint16", uint16(15), 15},
		{"uint", uint(16), 16},
		{"unrecognized-string", "not-a-number", 0},
		{"nil", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := toInt(tc.in); got != tc.want {
				t.Errorf("toInt(%v): got %d want %d", tc.in, got, tc.want)
			}
		})
	}
}

// ----- toUint64 -----

func TestToUint64_AllNumericTypes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want uint64
	}{
		{"uint64", uint64(7), 7},
		{"int64", int64(8), 8},
		{"int", int(9), 9},
		{"uint", uint(10), 10},
		{"unrecognized", "nope", 0},
		{"nil", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := toUint64(tc.in); got != tc.want {
				t.Errorf("toUint64(%v): got %d want %d", tc.in, got, tc.want)
			}
		})
	}
}

// ----- toByteSlices -----

func TestToByteSlices_NativeSlice(t *testing.T) {
	in := [][]byte{{0x01}, {0x02}}
	got, err := toByteSlices(in)
	if err != nil {
		t.Fatalf("toByteSlices: %v", err)
	}
	if len(got) != 2 || got[0][0] != 0x01 {
		t.Errorf("got %v", got)
	}
}

func TestToByteSlices_AnyArrayWithBytes(t *testing.T) {
	in := []any{[]byte{0x10}, []byte{0x20}}
	got, err := toByteSlices(in)
	if err != nil {
		t.Fatalf("toByteSlices: %v", err)
	}
	if len(got) != 2 || got[1][0] != 0x20 {
		t.Errorf("got %v", got)
	}
}

func TestToByteSlices_AnyArrayWithNonBytes(t *testing.T) {
	in := []any{[]byte{0x10}, "not-bytes"}
	if _, err := toByteSlices(in); err == nil {
		t.Error("expected error for non-bytes element")
	}
}

func TestToByteSlices_UnexpectedType(t *testing.T) {
	if _, err := toByteSlices(42); err == nil {
		t.Error("expected error for non-array input")
	}
}

// ----- rfc9162RootFromProof -----
//
// Two extra branches not exercised by the receipt round-trip tests:
//   - empty path with leafIndex+1 < treeSize → "proof path too short"
//   - path element with the wrong length

func TestRFC9162RootFromProof_TreeSizeZero(t *testing.T) {
	if _, err := rfc9162RootFromProof([sha256.Size]byte{}, 0, 0, nil); err == nil {
		t.Error("expected error for treeSize=0")
	}
}

func TestRFC9162RootFromProof_LeafBeyondTree(t *testing.T) {
	if _, err := rfc9162RootFromProof([sha256.Size]byte{}, 5, 4, nil); err == nil {
		t.Error("expected error for leafIndex >= treeSize")
	}
}

func TestRFC9162RootFromProof_ShortPath(t *testing.T) {
	// 4-leaf tree, leaf 2 ("right side") starts with fn=2 (binary 10).
	// With no path elements, the loop never runs and fn != 0 at the
	// end → "proof path too short" error fires.
	leafHash := rfc9162LeafHash([]byte("entry"))
	if _, err := rfc9162RootFromProof(leafHash, 2, 4, nil); err == nil {
		t.Error("expected error when path is too short for tree size")
	}
}

func TestRFC9162RootFromProof_BadElementLength(t *testing.T) {
	leafHash := rfc9162LeafHash([]byte("entry"))
	bogus := [][]byte{{0x01, 0x02}} // 2 bytes, not 32
	if _, err := rfc9162RootFromProof(leafHash, 0, 2, bogus); err == nil {
		t.Error("expected error for path element of wrong length")
	}
}

func TestRFC9162RootFromProof_SingleLeafTree(t *testing.T) {
	// treeSize=1, leafIndex=0, no path needed → root == leaf hash.
	leafHash := rfc9162LeafHash([]byte("only"))
	root, err := rfc9162RootFromProof(leafHash, 0, 1, nil)
	if err != nil {
		t.Fatalf("single-leaf proof: %v", err)
	}
	if !bytes.Equal(root[:], leafHash[:]) {
		t.Error("single-leaf root must equal the leaf hash")
	}
}
