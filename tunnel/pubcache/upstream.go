package pubcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// upstream.go — the ONLY outbound surface of this role, and the one place SSRF
// could have crept in. It is closed structurally rather than by filtering:
//
//   - Upstream base URLs come from OPERATOR CONFIG ONLY. There is no header, no
//     query parameter, and no path segment by which a client can name a host to
//     fetch from. The client supplies a content ADDRESS; this node decides where
//     to look for it. A URL blocklist would be a filter to get wrong; a config
//     allowlist is a filter that cannot be bypassed.
//   - Base URLs are validated once, at construction: http/https only, no
//     userinfo, host required, and the address is appended as a path segment
//     that is already known to be canonical base64url (ParseAddr), so no
//     traversal, no scheme smuggling, no injected query.
//   - Redirects are NOT followed. A 302 from an upstream is exactly the vector
//     an allowlist would otherwise leak through, so a redirect is a failure.
//
// Fan-out is bounded on three axes: a global in-flight semaphore, sequential
// (never parallel) upstream attempts per request, and single-flight coalescing
// so a thundering herd for one cold object becomes ONE upstream fetch.

// ErrNotServed is the § 22.6.2 refusal (ERR_PUB_NOT_SERVED, 0x090C): this holder
// does not have the object and could not obtain a verifiable copy. A fetcher's
// correct response is to rotate to another holder, not to trust this one.
var ErrNotServed = errors.New("pubcache: object not served by this holder")

// parseUpstreams validates the operator-configured gateway list.
func parseUpstreams(raw []string) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("pubcache: bad upstream %q: %w", s, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("pubcache: upstream %q must be http or https", s)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("pubcache: upstream %q has no host", s)
		}
		if u.User != nil {
			return nil, fmt.Errorf("pubcache: upstream %q must not carry credentials", s)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("pubcache: upstream %q must not carry a query or fragment", s)
		}
		u.Path = strings.TrimSuffix(u.Path, "/")
		out = append(out, u)
	}
	return out, nil
}

// upstreamURL builds a read URL under an operator-configured base. Every
// component is either fixed by this code or already validated as canonical
// base64url, so the result cannot escape the configured origin.
func upstreamURL(base *url.URL, suffix string) string {
	u := *base
	u.Path = base.Path + suffix
	return u.String()
}

// fetcher performs bounded, coalesced upstream reads.
type fetcher struct {
	client    *http.Client
	upstreams []*url.URL
	maxBytes  int64

	sem chan struct{} // global in-flight bound

	mu     sync.Mutex
	flight map[string]*flight // single-flight, keyed by cache key
}

type flight struct {
	done chan struct{}
	body []byte
	ct   string
	err  error
}

func newFetcher(client *http.Client, upstreams []*url.URL, maxBytes int64, maxInflight int) *fetcher {
	if maxInflight <= 0 {
		maxInflight = 1
	}
	return &fetcher{
		client:    client,
		upstreams: upstreams,
		maxBytes:  maxBytes,
		sem:       make(chan struct{}, maxInflight),
		flight:    make(map[string]*flight),
	}
}

// do fetches suffix from the configured upstreams, coalescing concurrent
// requests that share coalesceKey. It returns the body and the upstream's
// content type.
func (f *fetcher) do(ctx context.Context, coalesceKey, suffix string) ([]byte, string, error) {
	if len(f.upstreams) == 0 {
		return nil, "", ErrNotServed
	}
	// An empty key opts OUT of coalescing (mutable reads), rather than sharing
	// one bucket — two feed reads must never be answered from one response.
	if coalesceKey == "" {
		return f.fetch(ctx, suffix)
	}

	f.mu.Lock()
	if fl, ok := f.flight[coalesceKey]; ok {
		f.mu.Unlock()
		select {
		case <-fl.done:
			return fl.body, fl.ct, fl.err
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	fl := &flight{done: make(chan struct{})}
	f.flight[coalesceKey] = fl
	f.mu.Unlock()

	fl.body, fl.ct, fl.err = f.fetch(ctx, suffix)
	close(fl.done)

	f.mu.Lock()
	delete(f.flight, coalesceKey)
	f.mu.Unlock()

	return fl.body, fl.ct, fl.err
}

// fetch tries each configured upstream in order until one answers. Sequential on
// purpose: parallel fan-out would multiply this node's load onto the swarm every
// time an object is missing, which is the classic way a cache becomes an
// amplifier.
func (f *fetcher) fetch(ctx context.Context, suffix string) ([]byte, string, error) {
	select {
	case f.sem <- struct{}{}:
		defer func() { <-f.sem }()
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}

	var lastErr error = ErrNotServed
	for _, base := range f.upstreams {
		body, ct, err := f.fetchOne(ctx, base, suffix)
		if err == nil {
			return body, ct, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
	}
	return nil, "", lastErr
}

func (f *fetcher) fetchOne(ctx context.Context, base *url.URL, suffix string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL(base, suffix), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/cbor, application/octet-stream")
	req.Header.Set("User-Agent", "vulos-relayd-pubcache/1 (DMTAP-PUB cache role)")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%w: upstream %s returned %d", ErrNotServed, base.Host, resp.StatusCode)
	}
	// Read at most maxBytes+1 so an over-cap body is DETECTED rather than
	// silently truncated — a truncated object would fail verification anyway,
	// but failing on the size explicitly keeps the reason honest.
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > f.maxBytes {
		return nil, "", fmt.Errorf("%w: upstream object exceeds %d-byte cap", ErrNotServed, f.maxBytes)
	}
	return body, resp.Header.Get("Content-Type"), nil
}
