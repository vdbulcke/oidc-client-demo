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

	config.ClientID = "foo"
	config.ClientSecret = "bar"

	if !ValidateConfig(config) {
		t.Fail()
	}
	t.Logf("Config %v", config)

	// t.Fail()
}
