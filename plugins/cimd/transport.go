package cimd

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/node.ts: an HTTPS transport for CIMD-owned resources with
// resolve-once DNS validation and connection pinning.

// TransportOptions customise NewClientMetadataResourceFetch (tests and custom networks).
type TransportOptions struct {
	// LookupIPAddr resolves a hostname (default net.DefaultResolver.LookupIPAddr).
	LookupIPAddr func(ctx context.Context, host string) ([]net.IPAddr, error)
	// DialContext dials the pinned address (default a net.Dialer with a 10s timeout).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLSConfig is the base TLS client configuration; ServerName is always set to the
	// URL hostname (no SNI for IP literals).
	TLSConfig *tls.Config
}

// FetchClientMetadataResource fetches a CIMD-owned HTTPS resource with resolve-once DNS
// validation and connection pinning (fetchClientMetadataResource). Every DNS answer must be
// public-routable; the first answer is pinned for the connection while the original
// hostname remains the HTTP Host, TLS SNI and certificate-verification identity. Redirect
// responses are returned to the caller and never followed. Only GET and HEAD are
// supported.
var FetchClientMetadataResource oauthprovider.ClientMetadataResourceFetch = NewClientMetadataResourceFetch(TransportOptions{})

// closeTransportBody closes the per-request transport with the body.
type closeTransportBody struct {
	io.ReadCloser
	tr *http.Transport
}

func (b closeTransportBody) Close() error {
	err := b.ReadCloser.Close()
	b.tr.CloseIdleConnections()
	return err
}

// NewClientMetadataResourceFetch returns the pinned-connection transport with custom
// resolver, dialer or TLS settings.
func NewClientMetadataResourceFetch(o TransportOptions) oauthprovider.ClientMetadataResourceFetch {
	lookup := o.LookupIPAddr
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	dial := o.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	return func(req *http.Request) (*http.Response, error) {
		if req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") {
			return nil, errors.New("CIMD transport requires an HTTPS URL")
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != "" {
			return nil, errors.New("CIMD transport supports only GET and HEAD")
		}
		ctx := req.Context()
		hostname := req.URL.Hostname()
		addrs, err := lookup(ctx, hostname)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, errors.New("metadata hostname returned no DNS addresses")
		}
		for _, a := range addrs {
			if !isPublicRoutableHost(a.IP.String()) {
				return nil, errors.New("metadata hostname must resolve only to public-routable addresses")
			}
		}
		port := req.URL.Port()
		if port == "" {
			port = "443"
		}
		pinned := net.JoinHostPort(addrs[0].IP.String(), port)
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if o.TLSConfig != nil {
			tlsConfig = o.TLSConfig.Clone()
		}
		if net.ParseIP(hostname) == nil {
			tlsConfig.ServerName = hostname
		} else {
			tlsConfig.ServerName = ""
		}
		tr := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dial(ctx, network, pinned)
			},
			TLSClientConfig:   tlsConfig,
			DisableKeepAlives: true,
		}
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		res, err := client.Do(req)
		if err != nil {
			tr.CloseIdleConnections()
			return nil, err
		}
		if res.Body != nil {
			res.Body = closeTransportBody{res.Body, tr}
		}
		return res, nil
	}
}
