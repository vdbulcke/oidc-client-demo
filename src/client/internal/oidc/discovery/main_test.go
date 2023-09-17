package discovery

import (
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestWellKnown(t *testing.T) {

	issuer := "https://accounts.google.com"
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	w, err := NewWellKnown(wellKnown)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	l := hclog.Default()

	if !ValidWellKnown(w, issuer, l) {
		t.Fail()
	}

}
