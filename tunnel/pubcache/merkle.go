package pubcache

import "github.com/zeebo/blake3"

// merkle.go — the § 22.2.2 DS-tagged Merkle tree over PLAINTEXT chunk hashes.
//
// This is the construction that makes a PubManifest self-addressing, and the
// domain-separation tag is the load-bearing part: because "DMTAP-PUB-v0/manifest"
// is folded into every leaf AND every node, a public root and a SEALED root
// (§ 18.9.5, bare 0x00/0x01 tags over ciphertext chunk hashes) over the same
// chunk-hash list are different values. The object's TYPE is bound into its
// address rather than asserted by a flag, so a sealed manifest mis-served as a
// public one cannot verify here — it fails closed as an address mismatch
// (ERR_PUB_MANIFEST_TYPE_MISMATCH, 0x0903), never "tried both ways" (§ 22.2.3).

// dsManifest is the § 22.2.2 domain-separation tag: "DMTAP-PUB-v0/manifest" ‖ 0x00.
var dsManifest = append([]byte("DMTAP-PUB-v0/manifest"), 0x00)

// merkleLeaf = BLAKE3-256( DS ‖ 0x00 ‖ h_i ), over the FULL 33-byte chunk
// address (prefix ‖ digest), per § 22.2.2.
func merkleLeaf(h Addr) [32]byte {
	d := blake3.New()
	_, _ = d.Write(dsManifest)
	_, _ = d.Write([]byte{0x00})
	_, _ = d.Write(h[:])
	var out [32]byte
	copy(out[:], d.Sum(nil))
	return out
}

// merkleNode = BLAKE3-256( DS ‖ 0x01 ‖ left ‖ right ), per § 22.2.2.
func merkleNode(left, right [32]byte) [32]byte {
	d := blake3.New()
	_, _ = d.Write(dsManifest)
	_, _ = d.Write([]byte{0x01})
	_, _ = d.Write(left[:])
	_, _ = d.Write(right[:])
	var out [32]byte
	copy(out[:], d.Sum(nil))
	return out
}

// merkleRoot computes MTH(h_0 … h_{n-1}) using the RFC 6962 split rule
// (k = the largest power of two strictly less than n), iteratively rather than
// recursively so a manifest with a very long chunk list cannot exhaust the
// stack. hashes MUST be non-empty.
func merkleRoot(hashes []Addr) [32]byte {
	n := len(hashes)
	if n == 1 {
		return merkleLeaf(hashes[0])
	}
	// Explicit stack of (subtree root, subtree leaf-count) in left-to-right
	// order. RFC 6962's split rule is exactly "merge the two rightmost subtrees
	// whenever the right one is not larger than the left", which the pairing
	// below reproduces without recursion.
	type frame struct {
		root  [32]byte
		count int
	}
	stack := make([]frame, 0, 32)
	for _, h := range hashes {
		f := frame{root: merkleLeaf(h), count: 1}
		for len(stack) > 0 && stack[len(stack)-1].count == f.count {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			f = frame{root: merkleNode(top.root, f.root), count: top.count + f.count}
		}
		stack = append(stack, f)
	}
	// Fold any leftover subtrees right-to-left: with the RFC 6962 split rule the
	// left subtree of the root is always the largest power of two below n, which
	// is precisely what remains on the stack in decreasing size.
	acc := stack[len(stack)-1]
	for i := len(stack) - 2; i >= 0; i-- {
		acc = frame{root: merkleNode(stack[i].root, acc.root), count: stack[i].count + acc.count}
	}
	return acc.root
}

// ManifestRoot is the public content address of a manifest with the given
// ordered plaintext chunk addresses: `0x1e ‖ MTH(h_0 … h_{n-1})` (§ 22.2.2).
func ManifestRoot(chunks []Addr) Addr {
	root := merkleRoot(chunks)
	var a Addr
	a[0] = HashPrefixBLAKE3_256
	copy(a[1:], root[:])
	return a
}
