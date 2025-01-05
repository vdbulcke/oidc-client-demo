package http

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/creasty/defaults"
	"github.com/hashicorp/go-hclog"
)

type HttpClientConfig struct {
	// MaxIdleConns controls the maximum number of idle (keep-alive)
	// connections across all hosts. Zero means no limit.
	MaxIdleConns int `yaml:"max_idle_conns" default:"10" `

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle
	// (keep-alive) connections to keep per-host. If zero,
	// DefaultMaxIdleConnsPerHost is used.
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host" default:"10" `

	// MaxConnsPerHost optionally limits the total number of
	// connections per host, including connections in the dialing,
	// active, and idle states. On limit violation, dials will block.

	// Zero means no limit.
	MaxConnsPerHost int `yaml:"max_conns_per_host"  default:"10" `

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time, any
	// redirects, and reading the response body. The timer remains
	// running after Get, Head, Post, or Do return and will
	// interrupt reading of the Response.Body.

	// A Timeout of zero means no timeout.

	// The Client cancels requests to the underlying Transport
	// as if the Request's Context ended.
	Timeout time.Duration `yaml:"timeout_duration" default:"10s"`

	InsecureSkipVerify bool `yaml:"skip_tls_verification" default:"false"`

	MaxRespSizeLimitBytes int64 `yaml:"limit_max_resp_size_limit" default:"60000"`

	ExtraHeader map[string]string `yaml:"extra_headers"`
}

func (c *HttpClientConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// source: https://stackoverflow.com/questions/56049589/what-is-the-way-to-set-default-values-on-keys-in-lists-when-unmarshalling-yaml-i
	// set default
	err := defaults.Set(c)
	if err != nil {
		return err
	}

	type plain HttpClientConfig

	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	return nil

}

// NewDefaultHttpClientCfg create a default config
func NewDefaultHttpClientCfg() *HttpClientConfig {

	cfg := &HttpClientConfig{}
	err := defaults.Set(cfg)
	if err != nil {
		panic(err)
	}

	return cfg
}

// NewHttpClient Create new http.Transport initialize according
// to HttpClientConfig
func NewHttpTransport(c *HttpClientConfig, logger hclog.Logger, clientCerts []tls.Certificate) http.RoundTripper {

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxConnsPerHost = c.MaxConnsPerHost
	t.MaxIdleConns = c.MaxIdleConns
	t.MaxIdleConnsPerHost = c.MaxIdleConnsPerHost

	if len(clientCerts) > 0 {
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: c.InsecureSkipVerify,
			Certificates:       clientCerts,
		}

	} else {

		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: c.InsecureSkipVerify,
		}
	}

	return NewLogTransport(t, logger)
}

func NewHttpClient(c *HttpClientConfig, logger hclog.Logger, clientCerts []tls.Certificate) *http.Client {
	t := NewHttpTransport(c, logger, clientCerts)
	return &http.Client{
		// http noRedirect client GO black magic
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout:   c.Timeout,
		Transport: t,
	}
}
