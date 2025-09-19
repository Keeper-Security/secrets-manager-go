package test

import (
	"os"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestProxyUrlArgument(t *testing.T) {
	proxyUrl := "http://myproxy:9999"

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)

	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config, ProxyUrl: proxyUrl})

	if sm.ProxyUrl != proxyUrl {
		t.Errorf("Expected ProxyUrl to be %s from argument, got %s", proxyUrl, sm.ProxyUrl)
	}
}

func TestProxyUrlDefaultEmpty(t *testing.T) {
	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)

	// Do not pass ProxyUrl argument
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config})

	if sm.ProxyUrl != "" {
		t.Errorf("Expected ProxyUrl to be empty when neither env var nor argument is set, got %s", sm.ProxyUrl)
	}
}
