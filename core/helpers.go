package core

import (
	"net"
	"net/url"
	"os"
	"strings"

	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

func GetServerHostname(hostname string, configStore IKeyValueStorage) string {
	hostnameToUse := defaultKeeperHostname
	if envHostname := strings.TrimSpace(os.Getenv("KSM_HOSTNAME")); envHostname != "" {
		hostnameToUse = envHostname
	} else if cfgHostname := strings.TrimSpace(configStore.Get(KEY_HOSTNAME)); cfgHostname != "" {
		hostnameToUse = cfgHostname
	} else if codedHostname := strings.TrimSpace(hostname); codedHostname != "" {
		hostnameToUse = codedHostname
	}

	// Parse URL to get only domain:
	hostnameToUse = strings.TrimSpace(hostnameToUse)
	hostnameToReturn := hostnameToUse

	if !strings.HasPrefix(strings.ToLower(hostnameToUse), "http") {
		hostnameToUse = "https://" + hostnameToUse
	}
	if u, err := url.Parse(hostnameToUse); err == nil && u.Host != "" {
		hostnameToReturn = u.Host
		if host, _, err := net.SplitHostPort(u.Host); err == nil && host != "" {
			hostnameToReturn = host
		}
	}

	klog.Debug("Keeper server hostname: " + hostnameToReturn)

	return hostnameToReturn
}
