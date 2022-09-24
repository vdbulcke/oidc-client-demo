package discovery

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-playground/validator"
	"github.com/hashicorp/go-hclog"
)

func NewWellKnown(wellKnown string) (*OIDCWellKnownOpenidConfiguration, error) {

	resp, err := http.Get(wellKnown)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var w OIDCWellKnownOpenidConfiguration
	err = json.Unmarshal(body, &w)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	err = json.Unmarshal(body, &w.WellKnownRaw)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery RAW object: %v", err)
	}

	return &w, nil
}

// ValidWellKnown validate config
func ValidWellKnown(w *OIDCWellKnownOpenidConfiguration, issuer string, logger hclog.Logger) bool {

	issuer = strings.TrimSuffix(issuer, "/")
	if issuer != w.Issuer {
		logger.Error("Issuer not matching discovery", "issuer", issuer, "discovery", w.Issuer)
		return false
	}

	validate := validator.New()
	errs := validate.Struct(w)

	if errs == nil {
		return true
	}

	for _, e := range errs.(validator.ValidationErrors) {
		logger.Error("validation error", "error", e)
	}

	return false

}
