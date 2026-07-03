package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
)

// Grant is a single agent's authorization: a token and the exact set of names it
// is allowed to serve. The server never lets an agent claim a name outside its
// grant, and never lets two live agents hold the same name at once.
type Grant struct {
	// Token is the bearer secret the agent presents. Compared in constant time.
	Token string
	// Names is the set of names this token may serve. A name maps to
	// <name>.<relay-domain> (subdomain mode) and /t/<name>/ (path mode).
	Names []string
}

// TokenStore validates a presented (token, name) pair. Implementations must use
// constant-time comparison and MUST fail closed.
type TokenStore interface {
	// Authorize returns nil if token is valid AND authorized to serve name.
	// It returns a non-nil error otherwise (never leaked verbatim to clients).
	Authorize(token, name string) error
}

// staticTokenStore is an in-memory store built from a fixed list of grants. It is
// the default (config-file / env driven) store for a self-hosted relay.
type staticTokenStore struct {
	// byHash maps sha256(token) -> allowed name set. Hashing keeps raw tokens out
	// of the lookup map; the compare is still constant-time against the stored hash.
	byHash map[[32]byte]map[string]struct{}
}

// NewStaticTokenStore builds a TokenStore from grants. Empty tokens/names are
// rejected at construction so a misconfigured relay fails closed rather than open.
func NewStaticTokenStore(grants []Grant) (TokenStore, error) {
	s := &staticTokenStore{byHash: make(map[[32]byte]map[string]struct{})}
	for i, g := range grants {
		tok := strings.TrimSpace(g.Token)
		if tok == "" {
			return nil, fmt.Errorf("grant %d: empty token", i)
		}
		if len(g.Names) == 0 {
			return nil, fmt.Errorf("grant %d: no names authorized", i)
		}
		h := sha256.Sum256([]byte(tok))
		set := s.byHash[h]
		if set == nil {
			set = make(map[string]struct{})
			s.byHash[h] = set
		}
		for _, n := range g.Names {
			n = normalizeName(n)
			if n == "" {
				return nil, fmt.Errorf("grant %d: empty/invalid name", i)
			}
			set[n] = struct{}{}
		}
	}
	if len(s.byHash) == 0 {
		return nil, fmt.Errorf("token store: no grants configured (refusing to run open)")
	}
	return s, nil
}

func (s *staticTokenStore) Authorize(token, name string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("empty token")
	}
	h := sha256.Sum256([]byte(token))
	// Constant-time membership: iterate all known hashes, compare each, so timing
	// does not reveal which (if any) token matched.
	var matched map[string]struct{}
	var found int
	for kh, set := range s.byHash {
		if subtle.ConstantTimeCompare(h[:], kh[:]) == 1 {
			matched = set
			found = 1
		}
	}
	if found == 0 {
		return fmt.Errorf("unknown token")
	}
	if _, ok := matched[normalizeName(name)]; !ok {
		return fmt.Errorf("token not authorized for name %q", name)
	}
	return nil
}

// normalizeName lowercases and validates a name to a DNS-label-ish safe subset so
// it can be a subdomain and a path segment. Returns "" if invalid.
func normalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || len(name) > 63 {
		return ""
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return ""
		}
	}
	// No leading/trailing hyphen (valid DNS label).
	if name[0] == '-' || name[len(name)-1] == '-' {
		return ""
	}
	return name
}
