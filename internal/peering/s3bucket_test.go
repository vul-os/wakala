// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// mockS3 is a minimal in-memory S3-compatible HTTP server (path-style) good
// enough to exercise the S3Bucket client: PUT object, GET object, DELETE
// object, and ListObjectsV2. It is NOT a complete S3 implementation — it covers
// exactly the verbs S3Bucket uses, with correct XML for listing and the
// NoSuchKey 404 for a missing GET.
type mockS3 struct {
	mu      sync.Mutex
	bucket  string
	objects map[string][]byte
}

func newMockS3(bucket string) *mockS3 {
	return &mockS3{bucket: bucket, objects: map[string][]byte{}}
}

// objectName extracts the object key from a path-style request:
// "/<bucket>/<key...>".
func (m *mockS3) objectName(p string) (string, bool) {
	p = strings.TrimPrefix(p, "/")
	prefix := m.bucket + "/"
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	return strings.TrimPrefix(p, prefix), true
}

func (m *mockS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		m.handlePut(w, r)
	case http.MethodGet:
		// ListObjectsV2 is GET on the bucket with ?list-type=2; a GET with an
		// object key is a fetch.
		if name, ok := m.objectName(r.URL.Path); ok && name != "" {
			m.handleGet(w, r, name)
			return
		}
		if r.URL.Query().Get("list-type") == "2" || r.URL.Query().Has("prefix") || r.URL.Path == "/"+m.bucket || r.URL.Path == "/"+m.bucket+"/" {
			m.handleList(w, r)
			return
		}
		m.handleList(w, r)
	case http.MethodHead:
		m.handleHead(w, r)
	case http.MethodDelete:
		m.handleDelete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockS3) handlePut(w http.ResponseWriter, r *http.Request) {
	name, ok := m.objectName(r.URL.Path)
	if !ok || name == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// minio-go uses AWS v4 streaming signatures (aws-chunked) for PUT over
	// plain HTTP; a real S3 server decodes that framing. Decode it here so the
	// stored object is the raw payload.
	if strings.Contains(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING") {
		body = decodeAWSChunked(body)
	}
	m.mu.Lock()
	cp := make([]byte, len(body))
	copy(cp, body)
	m.objects[name] = cp
	m.mu.Unlock()
	w.Header().Set("ETag", `"`+fmt.Sprintf("%x", len(body))+`"`)
	w.WriteHeader(http.StatusOK)
}

func (m *mockS3) handleGet(w http.ResponseWriter, _ *http.Request, name string) {
	m.mu.Lock()
	body, ok := m.objects[name]
	m.mu.Unlock()
	if !ok {
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", name)
		return
	}
	// minio-go validates object metadata headers (Last-Modified, ETag,
	// Content-Length) when reading, so set them like a real S3 response.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.Header().Set("ETag", `"`+fmt.Sprintf("%x", len(body))+`"`)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (m *mockS3) handleHead(w http.ResponseWriter, r *http.Request) {
	name, ok := m.objectName(r.URL.Path)
	if !ok || name == "" {
		w.WriteHeader(http.StatusOK) // bucket head
		return
	}
	m.mu.Lock()
	body, exists := m.objects[name]
	m.mu.Unlock()
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.Header().Set("ETag", `"`+fmt.Sprintf("%x", len(body))+`"`)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
}

func (m *mockS3) handleDelete(w http.ResponseWriter, r *http.Request) {
	name, ok := m.objectName(r.URL.Path)
	if !ok || name == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	m.mu.Lock()
	delete(m.objects, name)
	m.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// listResult mirrors the ListObjectsV2 response subset minio-go parses.
type listResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	Name        string   `xml:"Name"`
	Prefix      string   `xml:"Prefix"`
	KeyCount    int      `xml:"KeyCount"`
	MaxKeys     int      `xml:"MaxKeys"`
	IsTruncated bool     `xml:"IsTruncated"`
	Contents    []listObject
}

type listObject struct {
	XMLName xml.Name `xml:"Contents"`
	Key     string   `xml:"Key"`
	Size    int64    `xml:"Size"`
	ETag    string   `xml:"ETag"`
}

func (m *mockS3) handleList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	m.mu.Lock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	m.mu.Unlock()
	sort.Strings(keys)

	res := listResult{
		Name:     m.bucket,
		Prefix:   prefix,
		KeyCount: len(keys),
		MaxKeys:  1000,
	}
	for _, k := range keys {
		m.mu.Lock()
		sz := int64(len(m.objects[k]))
		m.mu.Unlock()
		res.Contents = append(res.Contents, listObject{Key: k, Size: sz, ETag: `"x"`})
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(res)
}

// decodeAWSChunked decodes the AWS v4 streaming-signature (aws-chunked) body
// framing: a sequence of "<hexsize>;chunk-signature=<sig>\r\n<data>\r\n" chunks
// terminated by a zero-length chunk. A real S3 server does this server-side.
func decodeAWSChunked(b []byte) []byte {
	var out []byte
	for len(b) > 0 {
		// Find the chunk header line terminator.
		nl := bytes.Index(b, []byte("\r\n"))
		if nl < 0 {
			break
		}
		header := string(b[:nl])
		b = b[nl+2:]
		// header = "<hexsize>[;chunk-signature=...]"
		sizeHex := header
		if i := strings.IndexByte(header, ';'); i >= 0 {
			sizeHex = header[:i]
		}
		var size int
		if _, err := fmt.Sscanf(sizeHex, "%x", &size); err != nil {
			break
		}
		if size == 0 {
			break
		}
		if size > len(b) {
			size = len(b)
		}
		out = append(out, b[:size]...)
		b = b[size:]
		// Skip the trailing CRLF after the chunk data.
		if len(b) >= 2 && b[0] == '\r' && b[1] == '\n' {
			b = b[2:]
		}
	}
	return out
}

func writeS3Error(w http.ResponseWriter, status int, code, key string) {
	type s3Error struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
		Key     string   `xml:"Key"`
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_ = xml.NewEncoder(w).Encode(s3Error{Code: code, Message: code, Key: key})
}

// newTestS3Bucket starts the mock S3 server and returns an S3Bucket pointed at
// it (path-style, plain HTTP).
func newTestS3Bucket(t *testing.T, bucket string) (*S3Bucket, *httptest.Server, *mockS3) {
	t.Helper()
	mock := newMockS3(bucket)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	cl, err := minio.New(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4("AKIDTEST", "SECRETTEST", ""),
		Secure:       false,
		Region:       "auto",
		BucketLookup: minio.BucketLookupPath, // force path-style for httptest host
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	return newS3BucketWithClient(cl, bucket), srv, mock
}

// TestS3BucketPutGetListDelete exercises the full BucketClient surface against
// a mock S3 server: Put writes, Get reads it back, List enumerates by prefix,
// Delete removes, and a missing Get returns ErrObjectNotFound.
func TestS3BucketPutGetListDelete(t *testing.T) {
	b, _, _ := newTestS3Bucket(t, "relay-peers")
	ctx := context.Background()

	// Put two objects under the inbox prefix and one unrelated.
	want := []byte("opaque-envelope-bytes")
	if err := b.Put(ctx, "peers/inbox/recv/000-a.env", want); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if err := b.Put(ctx, "peers/inbox/recv/001-b.env", []byte("second")); err != nil {
		t.Fatalf("Put b: %v", err)
	}
	if err := b.Put(ctx, "peers/inbox/other/zzz.env", []byte("other")); err != nil {
		t.Fatalf("Put other: %v", err)
	}

	// Get returns the exact bytes.
	got, err := b.Get(ctx, "peers/inbox/recv/000-a.env")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get returned %q, want %q", got, want)
	}

	// List by prefix returns only the two recv objects.
	keys, err := b.List(ctx, "peers/inbox/recv/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(keys)
	wantKeys := []string{"peers/inbox/recv/000-a.env", "peers/inbox/recv/001-b.env"}
	if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("List = %v, want %v", keys, wantKeys)
	}

	// Delete one and confirm Get then returns ErrObjectNotFound.
	if err := b.Delete(ctx, "peers/inbox/recv/000-a.env"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Get(ctx, "peers/inbox/recv/000-a.env"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("Get after delete: want ErrObjectNotFound, got %v", err)
	}

	// Deleting a missing key is not an error.
	if err := b.Delete(ctx, "peers/inbox/recv/does-not-exist.env"); err != nil {
		t.Fatalf("Delete missing: want nil, got %v", err)
	}

	// Get of a never-written key is ErrObjectNotFound.
	if _, err := b.Get(ctx, "peers/inbox/recv/never.env"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("Get missing: want ErrObjectNotFound, got %v", err)
	}
}

// TestS3BucketRoundTripThroughCarrier proves the REAL S3 client drops into the
// existing BucketTransport/BucketIngestor §7–§8 path unchanged: an encrypted
// envelope written via the transport is fetched + accepted by the ingestor and
// then deleted — same contract as the in-memory MemBucket, no checks bypassed.
func TestS3BucketRoundTripThroughCarrier(t *testing.T) {
	sender, receiver, res := testPair(t)
	if err := res.Add(&PeerDescriptor{
		Domains:     []string{"send.example"},
		IdentityPub: sender.SignPub,
		KexPub:      sender.KexPub,
		Versions:    []string{ProtoV1},
		Suites:      []string{SuiteV1},
		Endpoint:    "bucket:peers/inbox/sender",
	}); err != nil {
		t.Fatal(err)
	}

	bucket, _, _ := newTestS3Bucket(t, "relay-peers")
	recvDesc, _ := res.Resolve(context.Background(), "recv.example")
	recvDesc.Endpoint = "bucket:peers/inbox/recv"

	// Seal a valid envelope and write it through the bucket transport.
	env := sealFixture(t, sender, receiver, res)
	transport := NewBucketTransport(bucket)
	if err := transport.Deliver(context.Background(), "bucket:peers/inbox/recv", MarshalEnvelope(env)); err != nil {
		t.Fatalf("transport.Deliver: %v", err)
	}

	// Ingest from the real S3 bucket and confirm the §7–§8 checks deliver it.
	sink := &collectingSink{}
	in := &BucketIngestor{
		Client:   bucket,
		Prefix:   "peers/inbox/recv",
		Receiver: bucketReceiver(receiver, res, sink),
	}
	if n := in.PollOnce(context.Background()); n != 1 {
		t.Fatalf("ingest delivered %d, want 1", n)
	}
	if sink.count() != 1 {
		t.Fatalf("sink got %d, want 1", sink.count())
	}
	// Object deleted after successful delivery.
	keys, err := bucket.List(context.Background(), "peers/inbox/recv/")
	if err != nil {
		t.Fatalf("List after ingest: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("want object deleted after delivery, %d remain: %v", len(keys), keys)
	}
}

// TestS3ConfigFromEnv proves env parsing: enabled only when endpoint set, and
// an error when partially configured.
func TestS3ConfigFromEnv(t *testing.T) {
	// No endpoint → not enabled, no error.
	t.Setenv("RELAY_BUCKET_S3_ENDPOINT", "")
	cfg, ok, err := S3ConfigFromEnv()
	if err != nil || ok {
		t.Fatalf("no endpoint: want (_, false, nil), got (%+v, %v, %v)", cfg, ok, err)
	}

	// Endpoint without bucket/keys → error (fail loud).
	t.Setenv("RELAY_BUCKET_S3_ENDPOINT", "t3.storage.dev")
	if _, _, err := S3ConfigFromEnv(); err == nil {
		t.Fatalf("partial config: want error, got nil")
	}

	// Fully configured → enabled, scheme defaults to HTTPS.
	t.Setenv("RELAY_BUCKET_S3_BUCKET", "relay-peers")
	t.Setenv("RELAY_BUCKET_S3_ACCESS_KEY", "AK")
	t.Setenv("RELAY_BUCKET_S3_SECRET_KEY", "SK")
	cfg, ok, err = S3ConfigFromEnv()
	if err != nil || !ok {
		t.Fatalf("full config: want (cfg, true, nil), got (%+v, %v, %v)", cfg, ok, err)
	}
	if cfg.Endpoint != "t3.storage.dev" || cfg.Bucket != "relay-peers" || !cfg.UseSSL {
		t.Fatalf("full config parsed wrong: %+v", cfg)
	}
	if cfg.Region != "auto" {
		t.Fatalf("default region = %q, want auto", cfg.Region)
	}
}
