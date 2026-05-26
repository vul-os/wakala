// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Bucket is a real S3/Tigris/MinIO-compatible BucketClient backed by the
// pure-Go minio-go SDK (CGO-free — keeps the relay build CGO_ENABLED=0). It
// implements the same BucketClient seam as MemBucket, so the store-and-forward
// peer carrier (BucketTransport / BucketIngestor) works across hosts against a
// shared object store. The in-memory MemBucket stays the default/test backend;
// this client is selected only when configured (see S3ConfigFromEnv).
//
// The bucket is a dumb carrier: envelopes are end-to-end encrypted + signed
// (envelope.go), so the object store provides no confidentiality or authenticity
// of its own, and the receiver's §7–§8 checks (Receiver.Accept / AcceptStored)
// remain the sole authority for accepting a message. A bucket operator who can
// read objects sees only opaque ciphertext; one who can write cannot forge a
// valid envelope. This client changes only the carrier, not those guarantees.
type S3Bucket struct {
	client *minio.Client
	bucket string
}

// S3Config configures an S3Bucket. Endpoint is the S3-compatible host (no
// scheme), e.g. "t3.storage.dev" for Tigris or "s3.amazonaws.com" / a MinIO
// host. UseSSL controls https (default true). Region is the bucket region
// (Tigris accepts "auto"). Keys are the access/secret pair.
type S3Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseSSL    bool
}

// S3ConfigFromEnv reads the S3 bucket configuration from environment variables.
// It returns (cfg, true, nil) when a bucket backend is fully configured, or
// (_, false, nil) when no S3 endpoint is set (caller falls back to MemBucket).
// A partially-configured backend (endpoint set but missing bucket/keys) is an
// error so a misconfiguration fails loudly rather than silently using memory.
//
// Environment variables:
//
//	RELAY_BUCKET_S3_ENDPOINT    S3-compatible host (e.g. t3.storage.dev). Enables the real client.
//	RELAY_BUCKET_S3_REGION      Region (default "auto" — works for Tigris).
//	RELAY_BUCKET_S3_BUCKET      Bucket name (required).
//	RELAY_BUCKET_S3_ACCESS_KEY  Access key id (required; or via secrets file at deploy).
//	RELAY_BUCKET_S3_SECRET_KEY  Secret access key (required).
//	RELAY_BUCKET_S3_INSECURE    Set 1/true to use plain HTTP (default: HTTPS).
func S3ConfigFromEnv() (S3Config, bool, error) {
	endpoint := strings.TrimSpace(os.Getenv("RELAY_BUCKET_S3_ENDPOINT"))
	if endpoint == "" {
		return S3Config{}, false, nil
	}
	cfg := S3Config{
		Endpoint:  stripScheme(endpoint),
		Region:    envOr("RELAY_BUCKET_S3_REGION", "auto"),
		Bucket:    strings.TrimSpace(os.Getenv("RELAY_BUCKET_S3_BUCKET")),
		AccessKey: strings.TrimSpace(os.Getenv("RELAY_BUCKET_S3_ACCESS_KEY")),
		SecretKey: os.Getenv("RELAY_BUCKET_S3_SECRET_KEY"),
		UseSSL:    !envTrue("RELAY_BUCKET_S3_INSECURE"),
	}
	// If the endpoint carried an explicit scheme, honor http→insecure.
	if strings.HasPrefix(endpoint, "http://") {
		cfg.UseSSL = false
	}
	var missing []string
	if cfg.Bucket == "" {
		missing = append(missing, "RELAY_BUCKET_S3_BUCKET")
	}
	if cfg.AccessKey == "" {
		missing = append(missing, "RELAY_BUCKET_S3_ACCESS_KEY")
	}
	if cfg.SecretKey == "" {
		missing = append(missing, "RELAY_BUCKET_S3_SECRET_KEY")
	}
	if len(missing) > 0 {
		return S3Config{}, false, fmt.Errorf("peering: RELAY_BUCKET_S3_ENDPOINT is set but %s missing — refusing to silently fall back to in-memory bucket", strings.Join(missing, ", "))
	}
	return cfg, true, nil
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envTrue(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func stripScheme(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimSuffix(s, "/")
}

// NewS3Bucket constructs an S3Bucket from cfg using the minio-go SDK.
func NewS3Bucket(cfg S3Config) (*S3Bucket, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("peering: S3 bucket endpoint is empty")
	}
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("peering: S3 bucket name is empty")
	}
	region := cfg.Region
	if region == "" {
		region = "auto"
	}
	cl, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: region,
	})
	if err != nil {
		return nil, fmt.Errorf("peering: S3 client init: %w", err)
	}
	return &S3Bucket{client: cl, bucket: cfg.Bucket}, nil
}

// newS3BucketWithClient wires a pre-built minio client (tests).
func newS3BucketWithClient(cl *minio.Client, bucket string) *S3Bucket {
	return &S3Bucket{client: cl, bucket: bucket}
}

// Put implements BucketClient. It overwrites any existing object at key.
func (b *S3Bucket) Put(ctx context.Context, key string, body []byte) error {
	_, err := b.client.PutObject(ctx, b.bucket, key, bytes.NewReader(body), int64(len(body)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("peering: s3 put %q: %w", key, err)
	}
	return nil
}

// List implements BucketClient: it returns all object keys under prefix.
func (b *S3Bucket) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for obj := range b.client.ListObjects(ctx, b.bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("peering: s3 list %q: %w", prefix, obj.Err)
		}
		keys = append(keys, obj.Key)
	}
	return keys, nil
}

// Get implements BucketClient. A missing key returns ErrObjectNotFound.
func (b *S3Bucket) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := b.client.GetObject(ctx, b.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		if isS3NotFound(err) {
			return nil, ErrObjectNotFound
		}
		return nil, fmt.Errorf("peering: s3 get %q: %w", key, err)
	}
	defer obj.Close()
	body, err := io.ReadAll(obj)
	if err != nil {
		// minio defers the real error (incl. NoSuchKey) to the first read.
		if isS3NotFound(err) {
			return nil, ErrObjectNotFound
		}
		return nil, fmt.Errorf("peering: s3 read %q: %w", key, err)
	}
	return body, nil
}

// Delete implements BucketClient. Deleting a missing key is not an error.
func (b *S3Bucket) Delete(ctx context.Context, key string) error {
	if err := b.client.RemoveObject(ctx, b.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		if isS3NotFound(err) {
			return nil
		}
		return fmt.Errorf("peering: s3 delete %q: %w", key, err)
	}
	return nil
}

// isS3NotFound reports whether err is an S3 "object/key does not exist" error.
func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	resp := minio.ToErrorResponse(err)
	switch resp.Code {
	case "NoSuchKey", "NoSuchObject", "NotFound":
		return true
	}
	return resp.StatusCode == http.StatusNotFound
}

// Compile-time interface check.
var _ BucketClient = (*S3Bucket)(nil)
