package core

import (
	"net/http"
	"net/url"
	"testing"
)

// TestGetTransportEnvProxyFieldSet verifies that when ProxyUrl is empty the
// transport's Proxy field is non-nil so HTTPS_PROXY/HTTP_PROXY env vars are
// honored (KSM-912). Before the fix, &http.Transport{} left Proxy nil.
func TestGetTransportEnvProxyFieldSet(t *testing.T) {
	tr := getTransport("", true)
	if tr.Proxy == nil {
		t.Fatal("transport.Proxy is nil when ProxyUrl is empty; HTTPS_PROXY/HTTP_PROXY env vars will be silently ignored (KSM-912)")
	}
}

// TestGetTransportExplicitProxyUrl verifies that an explicit ProxyUrl is wired
// into the transport and returns the expected proxy for outbound requests.
func TestGetTransportExplicitProxyUrl(t *testing.T) {
	const proxyAddr = "http://explicit.proxy.com:9999"
	tr := getTransport(proxyAddr, true)

	req, _ := http.NewRequest("GET", "https://keepersecurity.com", nil)
	got, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("transport.Proxy returned error: %v", err)
	}
	if got == nil {
		t.Fatal("expected proxy URL from explicit ProxyUrl, got nil")
	}
	want, _ := url.Parse(proxyAddr)
	if got.String() != want.String() {
		t.Errorf("expected proxy %s, got %s", want, got)
	}
}
