package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxJWKSBytes = 1 << 20

type RemoteKeys struct {
	Client      *http.Client
	MaxAge      time.Duration
	MinInterval time.Duration

	url         *url.URL
	allowHTTP   bool
	mu          sync.Mutex
	keys        map[string]ed25519.PublicKey
	fetchedAt   time.Time
	attemptedAt time.Time
}

type Option func(*RemoteKeys)

func AllowInsecureHTTP() Option {
	return func(r *RemoteKeys) { r.allowHTTP = true }
}

func WithRootCAs(pool *x509.CertPool) Option {
	return func(r *RemoteKeys) {
		transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = base.Clone()
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
		r.Client.Transport = transport
	}
}

func NewRemoteKeys(rawURL string, opts ...Option) (*RemoteKeys, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("authn: url do jwks inválida: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, errors.New("authn: url do jwks precisa ser http(s)://host/caminho, sem credenciais")
	}
	r := &RemoteKeys{
		url: u,
		Client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		MaxAge:      10 * time.Minute,
		MinInterval: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(r)
	}
	if u.Scheme == "http" && !r.allowHTTP && !isLoopback(u.Hostname()) {
		return nil, errors.New("authn: jwks por http:// só em localhost, use https:// ou AllowInsecureHTTP() em desenvolvimento")
	}
	return r, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (r *RemoteKeys) Key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key, found := r.keys[kid]
	fresh := time.Since(r.fetchedAt) < r.MaxAge
	if found && fresh {
		return key, nil
	}

	if time.Since(r.attemptedAt) >= r.MinInterval {
		r.attemptedAt = time.Now()
		keys, err := r.fetch(ctx)
		if err == nil {
			r.keys, r.fetchedAt = keys, time.Now()
			key, found = keys[kid]
		} else if !found {
			return nil, err
		}
	}

	if !found {
		return nil, ErrUnknownKey
	}
	return key, nil
}

func (r *RemoteKeys) fetch(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	req := (&http.Request{
		Method: http.MethodGet,
		URL:    r.url,
		Header: http.Header{"Accept": {"application/json"}},
		Host:   r.url.Host,
	}).WithContext(ctx)
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authn: buscando jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authn: jwks respondeu %d", resp.StatusCode)
	}

	var set JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
		return nil, fmt.Errorf("authn: jwks inválido: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		pub, err := k.PublicKey()
		if err != nil || k.Kid == "" {
			continue
		}
		keys[k.Kid] = pub
	}
	return keys, nil
}
