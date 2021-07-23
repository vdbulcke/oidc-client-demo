package oidcclient

import (
	"testing"
)

func TestHttpClientGetCert(t *testing.T) {
	configFile := "../example/config.yaml"

	config, err := ParseConfig(configFile)
	if err != nil {
		t.Logf("Error parsing config %s", err)
		t.Fail()
	}

	t.Logf("Config %v", config)

	// t.Fail()
}
