package test

import (
	"os"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestProxyUrlEnvVar(t *testing.T) {
	// Save and defer restore of KSM_PROXY
	origProxy := os.Getenv("KSM_PROXY")
	defer os.Setenv("KSM_PROXY", origProxy)

	testUrl := "http://localhost:8888"
	os.Setenv("KSM_PROXY", testUrl)

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)

	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config})

	if sm.ProxyUrl != testUrl {
		t.Errorf("Expected ProxyUrl to be %s from KSM_PROXY env var, got %s", testUrl, sm.ProxyUrl)
	}
}

func TestProxyUrlArgument(t *testing.T) {
	proxyUrl := "http://myproxy:9999"

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)

	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config, ProxyUrl: proxyUrl})

	if sm.ProxyUrl != proxyUrl {
		t.Errorf("Expected ProxyUrl to be %s from argument, got %s", proxyUrl, sm.ProxyUrl)
	}
}

func TestProxyUrlArgumentOverridesEnvVar(t *testing.T) {
	// Save and defer restore of KSM_PROXY
	origProxy := os.Getenv("KSM_PROXY")
	defer os.Setenv("KSM_PROXY", origProxy)

	envProxy := "http://envproxy:8080"
	argProxy := "http://argproxy:9090"

	os.Setenv("KSM_PROXY", envProxy)

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)

	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config, ProxyUrl: argProxy})

	if sm.ProxyUrl != argProxy {
		t.Errorf("Expected ProxyUrl to be %s (argument should override env), got %s", argProxy, sm.ProxyUrl)
	}
}

func TestProxyUrlDefaultEmpty(t *testing.T) {
	// Save and defer restore of KSM_PROXY
	origProxy := os.Getenv("KSM_PROXY")
	defer os.Setenv("KSM_PROXY", origProxy)

	// Unset KSM_PROXY
	os.Unsetenv("KSM_PROXY")

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)

	// Do not pass ProxyUrl argument
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config})

	if sm.ProxyUrl != "" {
		t.Errorf("Expected ProxyUrl to be empty when neither env var nor argument is set, got %s", sm.ProxyUrl)
	}
}
