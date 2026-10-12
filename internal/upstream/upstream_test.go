package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testSecret is the marker planted in test target URLs; every assertion that a
// message or a log line is URL-free greps for it.
const testSecret = "s3cr3t"

// testTarget is the provider URL the fetch tests use.
const testTarget = "https://upstream.example/sub?token=" + testSecret

// publicAddr is the address the fake resolver hands out for every name, so the
// fetch paths run without DNS.
var publicAddr = netip.MustParseAddr("93.184.216.34")

// publicLookup resolves every name to one public address.
func publicLookup(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{publicAddr}, nil
}

// providerHandler answers one request the way a fake provider would.
type providerHandler func(*http.Request) (*http.Response, error)

// providerTLS is the throwaway certificate the in-memory providers serve and
// the pool the test transports trust it through.
type providerTLS struct {
	cert  tls.Certificate
	roots *x509.CertPool
}

// testProviderTLS is built once per process: generating a key per test would
// cost more than the tests do. Its names cover every provider host the tests
// dial by name.
var testProviderTLS = sync.OnceValues(func() (providerTLS, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return providerTLS{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "krot test provider"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"upstream.example", "mirror.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return providerTLS{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return providerTLS{}, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return providerTLS{
		cert:  tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		roots: roots,
	}, nil
})

// providerCertificate returns the test provider certificate, failing the test
// when it cannot be built.
func providerCertificate(t *testing.T) providerTLS {
	t.Helper()
	provider, err := testProviderTLS()
	if err != nil {
		t.Fatalf("build the test provider certificate: %v", err)
	}
	return provider
}

// fakeTransport builds the transport a test fetcher dials through: a real
// *http.Transport whose dialer hands the client one end of an in-memory pipe
// with a TLS provider serving handler on the other end. It is deliberately a
// real transport carrying a dialer of its own, because the fetcher installs
// the dial guard over a caller-supplied transport's dialer, and a double that
// never dials could not exercise that.
func fakeTransport(t *testing.T, handler providerHandler) *http.Transport {
	t.Helper()
	provider := providerCertificate(t)
	return &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: provider.roots},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go serveProvider(server, provider.cert, handler)
			return client, nil
		},
	}
}

// serveProvider answers the requests of one in-memory connection from handler,
// looping so a test's later fetches can reuse the connection, and closes it
// when the connection ends or the handler fails.
func serveProvider(conn net.Conn, cert tls.Certificate, handler providerHandler) {
	defer conn.Close()
	secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	reader := bufio.NewReader(secure)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		resp, err := handler(req)
		if err != nil {
			return
		}
		if err := resp.Write(secure); err != nil {
			return
		}
		_ = resp.Body.Close()
	}
}

// requestTarget rebuilds the target a provider was asked for: a server sees
// the request line and the Host header, not the absolute URL the fetcher built.
func requestTarget(req *http.Request) string {
	return "https://" + req.Host + req.URL.RequestURI()
}

// rawTransport is a RoundTripper the dial guard cannot be installed on: it has
// no dialer at all, so it stands for a caller-supplied client the fetcher must
// refuse rather than dial unguarded.
type rawTransport struct{}

// RoundTrip returns the error test fetchers must never reach.
func (rawTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unguarded transport reached")
}

// unusedTransport builds a transport double that fails the test when it is
// reached at all: the request must be refused before anything is dialed.
func unusedTransport(t *testing.T) *http.Transport {
	t.Helper()
	transport := fakeTransport(t, func(*http.Request) (*http.Response, error) {
		t.Error("request reached the provider, want it refused before dialing")
		return nil, errors.New("unreachable")
	})
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		t.Error("dial reached, want the request refused before dialing")
		return dial(ctx, network, addr)
	}
	return transport
}

// testFetcher builds a fetcher over the given transport double, with a
// resolver that maps every name onto one public address (IP literals are
// judged as they are, exactly as the process resolver does), and returns it
// with the buffer its log lines land in.
func testFetcher(t *testing.T, transport *http.Transport) (*fetcher, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	built := NewFetcher(&http.Client{Transport: transport}, slog.New(slog.NewTextHandler(logs, nil)))
	f, ok := built.(*fetcher)
	if !ok {
		t.Fatalf("NewFetcher returned %T, want *fetcher", built)
	}
	f.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if _, err := netip.ParseAddr(host); err == nil {
			return lookupNetIP(ctx, host)
		}
		return publicLookup(ctx, host)
	}
	// The in-memory providers serve one goroutine per connection, so the
	// fetcher's idle ones are closed with the test rather than left to the
	// process exiting.
	t.Cleanup(f.hc.CloseIdleConnections)
	return f, logs
}

// fakeResponse builds the response a fake provider returns for req. The
// protocol version and the content length are set because the response is
// written onto the wire by the in-memory provider, not handed to a
// RoundTripper as it is.
func fakeResponse(req *http.Request, status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(strings.NewReader(body)),
		Request:       req,
	}
}

// assertNoTarget fails when text repeats any of the given parts of a target
// URL: a provider URL carries the subscription secret in its query string.
func assertNoTarget(t *testing.T, text string, parts ...string) {
	t.Helper()
	for _, part := range parts {
		if strings.Contains(text, part) {
			t.Errorf("text repeats %q: %s", part, text)
		}
	}
}

func TestFetchRejectsBlockedTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "plain http", target: "http://upstream.example/sub?token=" + testSecret},
		{name: "loopback", target: "https://127.0.0.1/sub?token=" + testSecret},
		{name: "private 10/8", target: "https://10.1.2.3/sub?token=" + testSecret},
		{name: "private 172.16/12", target: "https://172.20.5.9/sub?token=" + testSecret},
		{name: "private 192.168/16", target: "https://192.168.1.10/sub?token=" + testSecret},
		{name: "ipv6 loopback", target: "https://[::1]/sub?token=" + testSecret},
		{name: "metadata v4", target: "https://169.254.169.254/latest/meta-data?token=" + testSecret},
		{name: "metadata v6", target: "https://[fd00:ec2::254]/sub?token=" + testSecret},
		{name: "carrier nat", target: "https://100.100.100.200/sub?token=" + testSecret},
		{name: "this network", target: "https://0.0.0.0/sub?token=" + testSecret},
		{name: "reserved", target: "https://255.255.255.255/sub?token=" + testSecret},
		{name: "mapped loopback", target: "https://[::ffff:127.0.0.1]/sub?token=" + testSecret},
		{name: "link-local v6", target: "https://[fe80::1]/sub?token=" + testSecret},
		{name: "6to4", target: "https://[2002:7f00:1::]/sub?token=" + testSecret},
		{name: "teredo", target: "https://[2001::1]/sub?token=" + testSecret},
		{name: "nat64 well-known", target: "https://[64:ff9b::7f00:1]/sub?token=" + testSecret},
		{name: "nat64 local use", target: "https://[64:ff9b:1::7f00:1]/sub?token=" + testSecret},
		{name: "multicast", target: "https://224.0.0.1/sub?token=" + testSecret},
		{name: "non-standard port", target: "https://upstream.example:8443/sub?token=" + testSecret},
		{name: "credentials in url", target: "https://user:pass@upstream.example/sub?token=" + testSecret},
		{name: "empty host", target: "https:///sub?token=" + testSecret},
		{name: "unparseable", target: "https://upstream.example/%zz?token=" + testSecret},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, logs := testFetcher(t, unusedTransport(t))
			res, err := f.Fetch(context.Background(), Request{URL: tt.target})
			if !errors.Is(err, ErrBlockedTarget) {
				t.Fatalf("Fetch(%q) error = %v, want ErrBlockedTarget", tt.name, err)
			}
			if res.Body != nil {
				t.Errorf("blocked target produced a body: %q", res.Body)
			}
			assertNoTarget(t, err.Error(), testSecret, "upstream.example")
			assertNoTarget(t, logs.String(), testSecret, "upstream.example")
		})
	}
}

func TestFetchRejectsNonPublicResolution(t *testing.T) {
	tests := []struct {
		name  string
		addrs []netip.Addr
	}{
		{name: "private", addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		{name: "public and private", addrs: []netip.Addr{publicAddr, netip.MustParseAddr("192.168.0.1")}},
		{name: "no addresses", addrs: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := testFetcher(t, unusedTransport(t))
			f.lookup = func(context.Context, string) ([]netip.Addr, error) { return tt.addrs, nil }
			if _, err := f.Fetch(context.Background(), Request{URL: testTarget}); !errors.Is(err, ErrBlockedTarget) {
				t.Fatalf("Fetch error = %v, want ErrBlockedTarget", err)
			}
		})
	}
}

func TestFetchRejectsUnresolvableHost(t *testing.T) {
	f, _ := testFetcher(t, unusedTransport(t))
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("no such host: upstream.example")
	}
	_, err := f.Fetch(context.Background(), Request{URL: testTarget})
	if !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("Fetch error = %v, want ErrBlockedTarget", err)
	}
	assertNoTarget(t, err.Error(), testSecret, "upstream.example")
}

func TestFetchRelaysIdentificationHeaders(t *testing.T) {
	relayed := map[string]string{
		"User-Agent": "Happ/1.2.3",
		"Hwid":       "device-id",
		"X-Ver-Os":   "14",
		"Device":     "pixel-7",
	}
	dropped := map[string]string{
		"Authorization":   "Bearer provider-secret",
		"Cookie":          "session=1",
		"X-Forwarded-For": "203.0.113.7",
		"Referer":         "https://krot.example/admin",
	}
	header := http.Header{}
	for name, value := range relayed {
		header.Set(name, value)
	}
	for name, value := range dropped {
		header.Set(name, value)
	}

	var (
		method string
		target string
		got    http.Header
	)
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		method, target, got = req.Method, requestTarget(req), req.Header.Clone()
		return fakeResponse(req, http.StatusOK, "body-1", nil), nil
	}))
	res, err := f.Fetch(context.Background(), Request{URL: testTarget, Header: header})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if method != http.MethodGet {
		t.Errorf("method = %q, want GET", method)
	}
	if target != testTarget {
		t.Errorf("target = %q, want %q", target, testTarget)
	}
	if string(res.Body) != "body-1" || res.NotModified {
		t.Errorf("result = %q (notModified %v), want the fresh body", res.Body, res.NotModified)
	}
	for name, want := range relayed {
		if value := got.Get(name); value != want {
			t.Errorf("relayed %s = %q, want %q", name, value, want)
		}
	}
	for name := range dropped {
		if value := got.Get(name); value != "" {
			t.Errorf("relayed %s = %q, want the header dropped", name, value)
		}
	}
}

func TestFetchServesFreshCacheHit(t *testing.T) {
	var calls atomic.Int64
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fakeResponse(req, http.StatusOK, "body-1", nil), nil
	}))
	ctx := context.Background()
	req := Request{URL: testTarget}

	first, err := f.Fetch(ctx, req)
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if first.NotModified {
		t.Error("first fetch reported as served from the cache")
	}
	second, err := f.Fetch(ctx, req)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if string(second.Body) != "body-1" || !second.NotModified {
		t.Errorf("second result = %q (notModified %v), want the cached body", second.Body, second.NotModified)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream requests = %d, want 1 (the second fetch must not leave krot)", got)
	}
}

func TestFetchRevalidatesAfterTTL(t *testing.T) {
	var (
		calls     atomic.Int64
		modifiers []string
	)
	now := time.Now()
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		modifiers = append(modifiers, req.Header.Get("If-None-Match"))
		if req.Header.Get("If-None-Match") == `"v1"` {
			return fakeResponse(req, http.StatusNotModified, "", nil), nil
		}
		return fakeResponse(req, http.StatusOK, "body-1", http.Header{"Etag": {`"v1"`}}), nil
	}))
	f.now = func() time.Time { return now }
	ctx := context.Background()
	req := Request{URL: testTarget}

	if _, err := f.Fetch(ctx, req); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	now = now.Add(defaultCacheTTL + time.Second)
	refreshed, err := f.Fetch(ctx, req)
	if err != nil {
		t.Fatalf("revalidating Fetch: %v", err)
	}
	if string(refreshed.Body) != "body-1" || !refreshed.NotModified {
		t.Errorf(
			"revalidated result = %q (notModified %v), want the cached body",
			refreshed.Body,
			refreshed.NotModified,
		)
	}
	if len(modifiers) != 2 || modifiers[0] != "" || modifiers[1] != `"v1"` {
		t.Errorf("If-None-Match = %q, want [\"\" \"v1\"]", modifiers)
	}

	// The 304 refreshed the entry, so the next fetch is a cache hit again.
	cached, err := f.Fetch(ctx, req)
	if err != nil {
		t.Fatalf("post-revalidation Fetch: %v", err)
	}
	if string(cached.Body) != "body-1" || !cached.NotModified {
		t.Errorf("post-revalidation result = %q (notModified %v)", cached.Body, cached.NotModified)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("upstream requests = %d, want 2", got)
	}
}

func TestFetchServesStaleCopyOnUpstreamFailure(t *testing.T) {
	var (
		calls  atomic.Int64
		status atomic.Int64
	)
	now := time.Now()
	f, logs := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if code := status.Load(); code != 0 {
			return fakeResponse(req, int(code), "", nil), nil
		}
		return fakeResponse(req, http.StatusOK, "body-1", nil), nil
	}))
	f.now = func() time.Time { return now }
	ctx := context.Background()
	req := Request{URL: testTarget}

	if _, err := f.Fetch(ctx, req); err != nil {
		t.Fatalf("warm Fetch: %v", err)
	}
	now = now.Add(defaultCacheTTL + time.Second)
	status.Store(http.StatusInternalServerError)
	stale, err := f.Fetch(ctx, req)
	if err != nil {
		t.Fatalf("Fetch during the outage: %v", err)
	}
	if string(stale.Body) != "body-1" || !stale.NotModified {
		t.Errorf("stale result = %q (notModified %v), want the cached body", stale.Body, stale.NotModified)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("upstream requests = %d, want 2", got)
	}
	assertNoTarget(t, logs.String(), testSecret, "upstream.example")
}

func TestFetchColdFailuresReturnErrors(t *testing.T) {
	statuses := []int{
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
		http.StatusFound,
	}
	for _, status := range statuses {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var (
				failing   atomic.Bool
				failures  atomic.Int64
				recovered atomic.Int64
			)
			f, logs := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
				if failing.Load() {
					failures.Add(1)
					return fakeResponse(req, status, "provider failure", nil), nil
				}
				recovered.Add(1)
				return fakeResponse(req, http.StatusOK, "body-1", nil), nil
			}))
			failing.Store(true)
			req := Request{URL: testTarget}
			if _, err := f.Fetch(context.Background(), req); err == nil {
				t.Fatalf("status %d returned no error", status)
			}
			if _, ok := f.fresh(testTarget); ok {
				t.Errorf("status %d was cached", status)
			}
			// A recovered provider is picked up by the next fetch.
			failing.Store(false)
			res, err := f.Fetch(context.Background(), req)
			if err != nil {
				t.Fatalf("Fetch after recovery: %v", err)
			}
			if string(res.Body) != "body-1" {
				t.Errorf("recovered body = %q, want body-1", res.Body)
			}
			if got := recovered.Load(); got != 1 {
				t.Errorf("upstream requests after recovery = %d, want 1", got)
			}
			if got := failures.Load(); got != 1 {
				t.Errorf("failing requests = %d, want 1", got)
			}
			assertNoTarget(t, logs.String(), testSecret, "upstream.example")
		})
	}
}

func TestFetchRejects304WithoutCache(t *testing.T) {
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		return fakeResponse(req, http.StatusNotModified, "", nil), nil
	}))
	if _, err := f.Fetch(context.Background(), Request{URL: testTarget}); err == nil {
		t.Fatal("304 without a cached copy returned no error")
	}
}

func TestFetchSharesConcurrentMisses(t *testing.T) {
	const callers = 8
	var (
		calls   atomic.Int64
		entered = make(chan struct{})
		release = make(chan struct{})
	)
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return fakeResponse(req, http.StatusOK, "shared-body", nil), nil
	}))
	ctx := context.Background()
	req := Request{URL: testTarget}

	errs := make(chan error, callers)
	results := make(chan Result, callers)
	for range callers {
		go func() {
			res, err := f.Fetch(ctx, req)
			errs <- err
			results <- res
		}()
	}
	<-entered
	// The leader is blocked inside the transport; a caller that did not join
	// the shared flight would have to be counted here already.
	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Errorf("concurrent upstream requests = %d, want 1", got)
	}
	close(release)
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Fetch: %v", err)
		}
		if res := <-results; string(res.Body) != "shared-body" {
			t.Errorf("body = %q, want shared-body", res.Body)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream requests = %d, want 1", got)
	}
}

func TestFetchFollowsPublicRedirect(t *testing.T) {
	var targets []string
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		targets = append(targets, requestTarget(req))
		if req.Host == "upstream.example" {
			return fakeResponse(req, http.StatusFound, "", http.Header{
				"Location": {"https://mirror.example/sub"},
			}), nil
		}
		return fakeResponse(req, http.StatusOK, "body-1", nil), nil
	}))
	res, err := f.Fetch(context.Background(), Request{URL: testTarget})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != "body-1" {
		t.Errorf("body = %q, want body-1", res.Body)
	}
	want := []string{testTarget, "https://mirror.example/sub"}
	if len(targets) != len(want) || targets[0] != want[0] || targets[1] != want[1] {
		t.Errorf("redirect chain = %q, want %q", targets, want)
	}
}

func TestFetchRejectsBlockedRedirect(t *testing.T) {
	var calls atomic.Int64
	f, logs := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fakeResponse(req, http.StatusFound, "", http.Header{
			"Location": {"https://10.0.0.1/internal?token=" + testSecret},
		}), nil
	}))
	_, err := f.Fetch(context.Background(), Request{URL: testTarget})
	if !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("Fetch error = %v, want ErrBlockedTarget", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream requests = %d, want 1 (the hop must not be followed)", got)
	}
	assertNoTarget(t, err.Error(), testSecret, "10.0.0.1")
	assertNoTarget(t, logs.String(), testSecret, "10.0.0.1", "upstream.example")
}

func TestFetchBoundsRedirectChain(t *testing.T) {
	var calls atomic.Int64
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fakeResponse(req, http.StatusFound, "", http.Header{
			"Location": {"https://upstream.example/next"},
		}), nil
	}))
	_, err := f.Fetch(context.Background(), Request{URL: testTarget})
	if !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("Fetch error = %v, want ErrBlockedTarget", err)
	}
	if got := calls.Load(); got != maxRedirects+1 {
		t.Errorf("upstream requests = %d, want %d", got, maxRedirects+1)
	}
}

func TestFetchPassesProfileHeadersThrough(t *testing.T) {
	upstream := http.Header{
		"Subscription-Userinfo":   {"upload=1; download=2; total=3"},
		"Profile-Title":           {"Provider"},
		"Profile-Update-Interval": {"12"},
		"Support-Url":             {"https://provider.example/support"},
		"Routing":                 {"happ://routing/onadd/cHJvZmlsZQ=="},
		"Content-Type":            {"text/plain; charset=utf-8"},
		"Set-Cookie":              {"session=1"},
	}
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		return fakeResponse(req, http.StatusOK, "body-1", upstream.Clone()), nil
	}))
	ctx := context.Background()
	req := Request{URL: testTarget}

	res, err := f.Fetch(ctx, req)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := res.ProfileHeaders.Get("Subscription-Userinfo"); got != "upload=1; download=2; total=3" {
		t.Errorf("subscription-userinfo = %q", got)
	}
	if got := res.ProfileHeaders.Get("Profile-Title"); got != "Provider" {
		t.Errorf("profile-title = %q", got)
	}
	if got := res.ProfileHeaders.Get("Profile-Update-Interval"); got != "12" {
		t.Errorf("profile-update-interval = %q", got)
	}
	if got := res.ProfileHeaders.Get("Support-Url"); got != "https://provider.example/support" {
		t.Errorf("support-url = %q", got)
	}
	for _, name := range []string{"Routing", "Set-Cookie", "Content-Type"} {
		if got := res.ProfileHeaders.Get(name); got != "" {
			t.Errorf("header %s = %q, want it not relayed", name, got)
		}
	}
	if res.ContentType != "text/plain; charset=utf-8" {
		t.Errorf("content type = %q", res.ContentType)
	}

	// Result headers belong to the caller: writing to them must not touch the
	// cached copy the next fetch of the same URL is served from.
	res.ProfileHeaders.Set("Routing", "happ://routing/onadd/cHJvZmlsZQ==")
	again, err := f.Fetch(ctx, req)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if got := again.ProfileHeaders.Get("Routing"); got != "" {
		t.Errorf("routing = %q, want a caller's write to stay out of the cache", got)
	}
}

func TestFetchDefaultsContentType(t *testing.T) {
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		return fakeResponse(req, http.StatusOK, "body-1", nil), nil
	}))
	res, err := f.Fetch(context.Background(), Request{URL: testTarget})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.ContentType != defaultContentType {
		t.Errorf("content type = %q, want %q", res.ContentType, defaultContentType)
	}
}

// TestFetchCapsResponseSize pins the per-response cap at the 2 MiB the fix
// requires: a body of exactly the cap is served, and one byte more is refused
// rather than truncated.
func TestFetchCapsResponseSize(t *testing.T) {
	const wantCap = 2 << 20
	if maxResponseBytes != wantCap {
		t.Errorf("maxResponseBytes = %d, want %d", maxResponseBytes, wantCap)
	}
	atCap := strings.Repeat("a", maxResponseBytes)
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		return fakeResponse(req, http.StatusOK, atCap, nil), nil
	}))
	res, err := f.Fetch(context.Background(), Request{URL: testTarget})
	if err != nil {
		t.Fatalf("Fetch at the cap: %v", err)
	}
	if len(res.Body) != maxResponseBytes {
		t.Errorf("body length = %d, want %d", len(res.Body), maxResponseBytes)
	}

	over, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		return fakeResponse(req, http.StatusOK, atCap+"a", nil), nil
	}))
	_, err = over.Fetch(context.Background(), Request{URL: testTarget})
	if err == nil {
		t.Fatal("oversized response returned no error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error = %v, want a size refusal", err)
	}
}

// TestSanitizeErrStripsTargets covers the error shapes a transport failure
// reaches sanitizeErr as: the URL-quoting *url.Error net/http wraps every
// failure in, and a cause that quotes a URL of its own.
func TestSanitizeErrStripsTargets(t *testing.T) {
	tests := []struct {
		err  error
		name string
	}{
		{
			name: "transport error quoting the url",
			err:  &url.Error{Op: http.MethodGet, URL: testTarget, Err: errors.New("connection refused")},
		},
		{
			name: "cause quoting another url",
			err: &url.Error{
				Op:  http.MethodGet,
				URL: testTarget,
				Err: errors.New(`failed to parse Location header "https://evil.example/` + testSecret + `"`),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized := sanitizeErr(tt.err)
			if sanitized == nil {
				t.Fatal("sanitizeErr returned nil")
			}
			assertNoTarget(t, sanitized.Error(), testSecret, "upstream.example", "evil.example")
		})
	}
}

// TestFetchNeverLeaksTarget drives a real transport failure through a whole
// fetch: neither the error nor the log line may repeat any part of the target.
func TestFetchNeverLeaksTarget(t *testing.T) {
	f, logs := testFetcher(t, &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
	})
	_, err := f.Fetch(context.Background(), Request{URL: testTarget})
	if err == nil {
		t.Fatal("transport failure returned no error")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want the cause kept without the URL", err)
	}
	assertNoTarget(t, err.Error(), testSecret, "upstream.example")
	assertNoTarget(t, logs.String(), testSecret, "upstream.example")
}

func TestBlockedAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{addr: "127.0.0.1", want: true},
		{addr: "::1", want: true},
		{addr: "10.0.0.1", want: true},
		{addr: "172.16.0.1", want: true},
		{addr: "172.31.255.255", want: true},
		{addr: "192.168.0.1", want: true},
		{addr: "169.254.169.254", want: true},
		{addr: "fe80::1", want: true},
		{addr: "fd00:ec2::254", want: true},
		{addr: "100.64.0.0", want: true},
		{addr: "100.100.100.200", want: true},
		{addr: "0.0.0.0", want: true},
		{addr: "255.255.255.255", want: true},
		{addr: "224.0.0.1", want: true},
		{addr: "::", want: true},
		{addr: "::ffff:127.0.0.1", want: true},
		{addr: "fe80::1%eth0", want: true},
		{addr: "2002::1", want: true},
		{addr: "2002:c0a8:101::1", want: true},
		{addr: "2001::1", want: true},
		{addr: "64:ff9b::7f00:1", want: true},
		{addr: "64:ff9b:1::7f00:1", want: true},
		{addr: "93.184.216.34", want: false},
		{addr: "8.8.8.8", want: false},
		{addr: "1.1.1.1", want: false},
		{addr: "2606:4700:4700::1111", want: false},
		{addr: "2001:4860:4860::8888", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := blockedAddr(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Errorf("blockedAddr(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestGuardDialerRefusesTargets(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		blocked bool
	}{
		{name: "non-standard port", addr: "upstream.example:8443", blocked: true},
		{name: "malformed address", addr: "upstream.example"},
		{name: "private address", addr: "10.0.0.1:443", blocked: true},
		{name: "loopback address", addr: "127.0.0.1:443", blocked: true},
		{name: "6to4 address", addr: "[2002:c0a8:101::1]:443", blocked: true},
		{name: "nat64 address", addr: "[64:ff9b::a00:1]:443", blocked: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer := &guardDialer{dial: (&net.Dialer{}).DialContext, lookup: lookupNetIP}
			conn, err := dialer.DialContext(context.Background(), "tcp", tt.addr)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("DialContext(%q) returned no error", tt.addr)
			}
			if tt.blocked && !errors.Is(err, ErrBlockedTarget) {
				t.Errorf("DialContext(%q) error = %v, want ErrBlockedTarget", tt.addr, err)
			}
		})
	}
}

func TestNewFetcherDefaults(t *testing.T) {
	built := NewFetcher(nil, nil)
	f, ok := built.(*fetcher)
	if !ok {
		t.Fatalf("NewFetcher returned %T, want *fetcher", built)
	}
	if f.hc == nil || f.hc.CheckRedirect == nil {
		t.Error("the default client is not wired with the redirect policy")
	}
	if f.hc.Timeout != defaultTimeout {
		t.Errorf("client timeout = %s, want %s", f.hc.Timeout, defaultTimeout)
	}
	if f.lookup == nil || f.now == nil {
		t.Error("the default seams are not installed")
	}
	if f.ttl != defaultCacheTTL {
		t.Errorf("ttl = %s, want %s", f.ttl, defaultCacheTTL)
	}
	if got := cap(f.slots); got != maxConcurrentFetches {
		t.Errorf("fetch slots = %d, want %d", got, maxConcurrentFetches)
	}
	if f.budget != maxCacheBytes {
		t.Errorf("cache budget = %d, want %d", f.budget, maxCacheBytes)
	}
	if f.unguarded {
		t.Error("the default fetcher reports an unguarded client")
	}

	template := &http.Transport{}
	client := &http.Client{Transport: template}
	NewFetcher(client, nil)
	if client.CheckRedirect != nil {
		t.Error("NewFetcher mutated the caller's client")
	}
	if template.DialContext != nil {
		t.Error("NewFetcher mutated the caller's transport")
	}
}

// TestNewFetcherFailsClosedOnUnguardedTransport checks the fail-closed path:
// a client whose transport cannot carry the dial guard is refused rather than
// dialed unguarded, and the refusal names what is wrong without naming any
// target.
func TestNewFetcherFailsClosedOnUnguardedTransport(t *testing.T) {
	tests := []struct {
		transport http.RoundTripper
		name      string
	}{
		{name: "not a transport", transport: rawTransport{}},
		{
			name: "dials tls itself",
			transport: &http.Transport{
				DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("unreachable")
				},
			},
		},
		{
			name: "proxies the dial",
			transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "https", Host: "proxy.example"}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &bytes.Buffer{}
			built := NewFetcher(
				&http.Client{Transport: tt.transport},
				slog.New(slog.NewTextHandler(logs, nil)),
			)
			f, ok := built.(*fetcher)
			if !ok {
				t.Fatalf("NewFetcher returned %T, want *fetcher", built)
			}
			res, err := f.Fetch(context.Background(), Request{URL: testTarget})
			if !errors.Is(err, ErrUnguardedClient) {
				t.Fatalf("Fetch error = %v, want ErrUnguardedClient", err)
			}
			if res.Body != nil {
				t.Errorf("unguarded fetcher produced a body: %q", res.Body)
			}
			assertNoTarget(t, err.Error(), testSecret, "upstream.example")
			assertNoTarget(t, logs.String(), testSecret, "upstream.example")
			if !strings.Contains(logs.String(), "cannot be guarded") {
				t.Errorf("log does not name the refusal: %s", logs.String())
			}
		})
	}
}

// TestFetchGuardsTemplateDialer points a rebinding resolver at a fetch through
// a caller-supplied transport: the pre-flight check sees a public address and
// the guard under the template's dial sees a private one, so the fetch must be
// refused before that dialer is reached at all.
func TestFetchGuardsTemplateDialer(t *testing.T) {
	var (
		resolutions atomic.Int64
		dials       atomic.Int64
	)
	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("the template dialer must not be reached")
		},
	}
	f, logs := testFetcher(t, transport)
	// The first resolution — the pre-flight check — hands out a public
	// address; every later one, the dial guard's, hands out a private one, as
	// a rebinding provider would.
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		if resolutions.Add(1) == 1 {
			return []netip.Addr{publicAddr}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}
	_, err := f.Fetch(context.Background(), Request{URL: testTarget})
	if !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("Fetch error = %v, want ErrBlockedTarget", err)
	}
	if got := dials.Load(); got != 0 {
		t.Errorf("template dialer calls = %d, want 0", got)
	}
	assertNoTarget(t, err.Error(), testSecret, "upstream.example")
	assertNoTarget(t, logs.String(), testSecret, "upstream.example")
}

// TestFetchSeparatesSessions checks that one client's fetch is never
// attributed to another: the same URL under a different session is a different
// cache entry and a different upstream request, the same session keeps sharing
// one, and the session identity itself never travels to the provider.
func TestFetchSeparatesSessions(t *testing.T) {
	const session = "session-marker"
	var (
		calls   atomic.Int64
		headers []http.Header
	)
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		headers = append(headers, req.Header.Clone())
		return fakeResponse(req, http.StatusOK, "body-1", nil), nil
	}))
	ctx := context.Background()

	tests := []struct {
		name    string
		session string
		cached  bool
	}{
		{name: "first session", session: session},
		{name: "first session again", session: session, cached: true},
		{name: "second session", session: "other-session"},
		{name: "second session again", session: "other-session", cached: true},
		{name: "no session"},
		{name: "no session again", cached: true},
	}
	for _, tt := range tests {
		res, err := f.Fetch(ctx, Request{URL: testTarget, SessionID: tt.session})
		if err != nil {
			t.Fatalf("%s: Fetch: %v", tt.name, err)
		}
		if string(res.Body) != "body-1" {
			t.Errorf("%s: body = %q, want body-1", tt.name, res.Body)
		}
		if res.NotModified != tt.cached {
			t.Errorf("%s: notModified = %v, want %v", tt.name, res.NotModified, tt.cached)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("upstream requests = %d, want 3 (one per session, plus the anonymous one)", got)
	}
	for index, header := range headers {
		for name, values := range header {
			if strings.Contains(strings.Join(values, " "), session) {
				t.Errorf("request %d relayed the session identity in %s", index, name)
			}
		}
	}
}

// TestFetchEvictsOldestBeyondCacheBudget fills the cache past its byte budget
// and checks both edges: the oldest entry is gone, the newest is served from
// the cache without another upstream request, and the cache is back under
// budget.
func TestFetchEvictsOldestBeyondCacheBudget(t *testing.T) {
	const (
		bodySize = 32
		budget   = 2 * bodySize
	)
	urls := []string{
		"https://upstream.example/first",
		"https://upstream.example/second",
		"https://upstream.example/third",
	}
	var calls atomic.Int64
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return fakeResponse(req, http.StatusOK, strings.Repeat("b", bodySize), nil), nil
	}))
	f.budget = budget
	now := time.Now()
	f.now = func() time.Time { return now }

	ctx := context.Background()
	for _, target := range urls {
		if _, err := f.Fetch(ctx, Request{URL: target}); err != nil {
			t.Fatalf("Fetch(%s): %v", target, err)
		}
		now = now.Add(time.Second)
	}
	if got := calls.Load(); got != int64(len(urls)) {
		t.Fatalf("upstream requests = %d, want %d", got, len(urls))
	}
	if got, want := f.bytes, 2*bodySize; got != want {
		t.Errorf("cached bytes = %d, want %d (the oldest entry must be evicted)", got, want)
	}
	for _, target := range urls {
		_, ok := f.fresh(cacheKey(target, ""))
		if want := target != urls[0]; ok != want {
			t.Errorf("fresh(%s) = %v, want %v", target, ok, want)
		}
	}

	// The newest entry is served from the cache; the oldest is a miss, so its
	// fetch goes upstream again and evicts the next-oldest entry in turn.
	newest, err := f.Fetch(ctx, Request{URL: urls[2]})
	if err != nil {
		t.Fatalf("Fetch(%s): %v", urls[2], err)
	}
	if !newest.NotModified {
		t.Error("the newest entry was refetched, want it served from the cache")
	}
	if _, err := f.Fetch(ctx, Request{URL: urls[0]}); err != nil {
		t.Fatalf("Fetch(%s): %v", urls[0], err)
	}
	if got := calls.Load(); got != int64(len(urls))+1 {
		t.Errorf("upstream requests = %d, want %d", got, len(urls)+1)
	}
	if f.bytes > f.budget {
		t.Errorf("cached bytes = %d, want at most the budget %d", f.bytes, f.budget)
	}
}

// TestFetchBoundsCacheByEntries checks the secondary bound: with bodies too
// small to matter to the byte budget, the entry count is still capped, the
// oldest entries fall off first and the newest stays.
func TestFetchBoundsCacheByEntries(t *testing.T) {
	const overflow = 3
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		return fakeResponse(req, http.StatusOK, "b", nil), nil
	}))
	f.budget = 1 << 30
	now := time.Now()
	f.now = func() time.Time { return now }

	ctx := context.Background()
	targets := make([]string, 0, maxCacheEntries+overflow)
	for index := range maxCacheEntries + overflow {
		target := "https://upstream.example/small-" + strconv.Itoa(index)
		targets = append(targets, target)
		if _, err := f.Fetch(ctx, Request{URL: target}); err != nil {
			t.Fatalf("Fetch(%s): %v", target, err)
		}
		now = now.Add(time.Millisecond)
	}
	if got := len(f.cache); got != maxCacheEntries {
		t.Errorf("cache entries = %d, want %d", got, maxCacheEntries)
	}
	for _, index := range []int{0, len(targets) - 1} {
		_, ok := f.fresh(cacheKey(targets[index], ""))
		if want := index == len(targets)-1; ok != want {
			t.Errorf("fresh(%s) = %v, want %v", targets[index], ok, want)
		}
	}
}

// TestAcquireFetchSlotHonoursContext checks the fetch bound from the inside: a
// waiter gives up when its context is done instead of queueing behind the
// bound, and takes a slot again once one is released.
func TestAcquireFetchSlotHonoursContext(t *testing.T) {
	f := &fetcher{slots: make(chan struct{}, 1)}
	if err := f.acquire(context.Background()); err != nil {
		t.Fatalf("acquire on a free slot: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("acquire error = %v, want context.Canceled", err)
	}
	f.release()
	if err := f.acquire(context.Background()); err != nil {
		t.Errorf("acquire after release: %v", err)
	}
}

// TestFetchBoundsConcurrentUpstreamFetches drives more distinct fetches than
// the fetcher may have in flight at once and watches the provider side: the
// bound must be reached and never passed, and every caller must be served once
// the provider lets go.
func TestFetchBoundsConcurrentUpstreamFetches(t *testing.T) {
	const callers = 3 * maxConcurrentFetches
	var (
		inFlight atomic.Int64
		peak     atomic.Int64
		release  = make(chan struct{})
	)
	f, _ := testFetcher(t, fakeTransport(t, func(req *http.Request) (*http.Response, error) {
		current := inFlight.Add(1)
		for {
			seen := peak.Load()
			if current <= seen || peak.CompareAndSwap(seen, current) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
		return fakeResponse(req, http.StatusOK, "body-1", nil), nil
	}))

	ctx := context.Background()
	results := make(chan error, callers)
	for index := range callers {
		go func() {
			target := "https://upstream.example/sub-" + strconv.Itoa(index)
			_, err := f.Fetch(ctx, Request{URL: target})
			results <- err
		}()
	}
	// Nothing is released yet, there are more callers than slots, and every
	// caller asks for its own URL, so every slot must be taken.
	deadline := time.Now().Add(5 * time.Second)
	for inFlight.Load() < maxConcurrentFetches && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := inFlight.Load(); got != maxConcurrentFetches {
		t.Fatalf("upstream fetches in flight = %d, want %d", got, maxConcurrentFetches)
	}
	// A caller that slipped past the bound would show up as a higher peak.
	time.Sleep(50 * time.Millisecond)
	if got := peak.Load(); got != maxConcurrentFetches {
		t.Errorf("peak upstream fetches = %d, want %d", got, maxConcurrentFetches)
	}
	close(release)
	for range callers {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Fetch: %v", err)
		}
	}
}
