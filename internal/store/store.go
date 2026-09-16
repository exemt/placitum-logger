package store

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var ErrGone = errors.New("store: object is gone")

const (
	ReasonAbsent = "absent"

	ReasonDiscarded = "discarded"

	ReasonTTL = "ttl_expired"

	ReasonExpired = "expired"

	ReasonDisabled = "store_disabled"

	ReasonDriver = "driver_unsupported"

	ReasonError = "store_error"
)

type Content struct {
	Reason  string
	Data    []byte
	Clipped bool
}

func (c Content) Available() bool { return c.Reason == "" }

type Reader struct {
	cfg Config
	s3  *s3Client
}

func New(cfg Config) *Reader {
	cfg.normalize()

	r := &Reader{cfg: cfg}

	if cfg.ArchiveEnabled() {
		r.s3 = &s3Client{
			endpoint: cfg.S3.Endpoint,
			region:   cfg.S3.Region,
			access:   cfg.S3.Access,
			secret:   cfg.S3.Secret,
			http: &http.Client{
				Timeout: cfg.OpTimeout,
				Transport: &http.Transport{
					MaxIdleConnsPerHost: 4,
					IdleConnTimeout:     90 * time.Second,
				},
			},
		}
	}

	return r
}

func (r *Reader) MaxBytes() int64 { return r.cfg.MaxBytes }

func (r *Reader) FetchWindow(ctx context.Context, kind string, loc Locator, ok bool, offset, limit int64) (Content, error) {
	if !ok {
		return Content{Reason: ReasonAbsent}, nil
	}

	if loc.Unavailable != "" {
		return Content{Reason: loc.Unavailable}, nil
	}

	if loc.Driver == "" || loc.Key == "" {
		return Content{Reason: ReasonDiscarded}, nil
	}

	if loc.Driver != "s3" {
		return Content{Reason: ReasonDriver}, nil
	}

	if loc.Expired(time.Now()) {
		return Content{Reason: ReasonTTL}, nil
	}

	bucket := r.cfg.Bucket[kind]

	if r.s3 == nil || bucket == "" {
		return Content{Reason: ReasonDisabled}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.OpTimeout)
	defer cancel()

	if limit <= 0 || limit > r.cfg.MaxBytes {
		limit = r.cfg.MaxBytes
	}

	data, clipped, err := r.s3.get(ctx, bucket, loc.Key, offset, limit)
	if errors.Is(err, ErrGone) {
		return Content{Reason: ReasonExpired}, nil
	}
	if err != nil {
		return Content{Reason: ReasonError}, err
	}

	if loc.Size > 0 && offset+int64(len(data)) < loc.Size {
		clipped = true
	}

	return Content{Data: data, Clipped: clipped}, nil
}
