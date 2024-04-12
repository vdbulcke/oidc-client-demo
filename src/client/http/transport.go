package http

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
)

type LogTransport struct {
	roundTripper http.RoundTripper

	// the Hashicor Logger
	logger hclog.Logger
}

func NewLogTransport(transport *http.Transport, logger hclog.Logger) http.RoundTripper {
	return &LogTransport{
		roundTripper: transport,
		logger:       logger,
	}
}

// RoundTrip is the core part of this module and implements http.RoundTripper.
// Executes HTTP request with request/response logging.
func (t *LogTransport) RoundTrip(req *http.Request) (*http.Response, error) {

	reqId := uuid.New().String()
	start := time.Now()

	if t.logger.IsDebug() {
		reqBody := []byte("nil")
		var err error
		if req.Body != nil {
			reqBody, err = io.ReadAll(req.Body)
			if err != nil {
				t.logger.Error("error parsing req body", "err", err)
			}
			// don't close body here
			req.Body = io.NopCloser(bytes.NewBuffer(reqBody))
		}

		reqStr := fmt.Sprintf("Method: %s\nUrl: %s\nHost: %s\nHeaders: %#v\nBody: %s", req.Method, req.URL, req.Host, req.Header, string(reqBody))
		t.logger.Debug("http.client request", "request_id", reqId, "req", reqStr)
	}

	resp, err := t.roundTripper.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	elasped_time := time.Since(start)

	if t.logger.IsDebug() {
		body, err := io.ReadAll(resp.Body)
		if err != nil {

			return resp, err
		}

		// don't close body here
		resp.Body = io.NopCloser(bytes.NewBuffer(body))

		respStr := fmt.Sprintf("Status: %s\nHeaders: %#v\nBody: %s", resp.Status, resp.Header, string(body))
		t.logger.Debug("http.client response", "request_id", reqId, "esplased", elasped_time, "resp", respStr)
	}
	return resp, err
}
