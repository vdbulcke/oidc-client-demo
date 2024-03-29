package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Token represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
//
// This type is a mirror of oauth2.Token and exists to break
// an otherwise-circular dependency. Other internal packages
// should convert this Token into an oauth2.Token before use.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time

	// Raw optionally contains extra metadata from the server
	// when updating a token.
	Raw interface{}
}

// Extra returns an extra field.
// Extra fields are key-value pairs returned by the server as a
// part of the token retrieval response.
func (t *Token) Extra(key string) interface{} {
	if raw, ok := t.Raw.(map[string]interface{}); ok {
		return raw[key]
	}

	vals, ok := t.Raw.(url.Values)
	if !ok {
		return nil
	}

	v := vals.Get(key)
	switch s := strings.TrimSpace(v); strings.Count(s, ".") {
	case 0: // Contains no "."; try to parse as int
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
	case 1: // Contains a single "."; try to parse as float
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}

	return v
}

func (t *Token) Type() string {
	return t.TokenType
}

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token or error in JSON form.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"` // at least PayPal returns string, while most return number
	// error fields
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	if i > math.MaxInt32 {
		i = math.MaxInt32
	}
	*e = expirationTime(i)
	return nil
}

// newTokenRequest returns a new *http.Request to retrieve a new token
// from tokenURL using the provided clientID, clientSecret, and POST
// body parameters.
//
// inParams is whether the clientID & clientSecret should be encoded
// as the POST body. An 'inParams' value of true means to send it in
// the POST body (along with any values in v); false means to send it
// in the Authorization header.
func newTokenRequest(tokenURL, clientID, clientSecret string, v url.Values, authStyle oauth2.AuthStyle) (*http.Request, error) {
	if authStyle == oauth2.AuthStyleInParams {
		v = cloneURLValues(v)
		if clientID != "" {
			v.Set("client_id", clientID)
		}
		if clientSecret != "" {
			v.Set("client_secret", clientSecret)
		}
	}
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authStyle == oauth2.AuthStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	return req, nil
}

func cloneURLValues(v url.Values) url.Values {
	v2 := make(url.Values, len(v))
	for k, vv := range v {
		v2[k] = append([]string(nil), vv...)
	}
	return v2
}

func RetrieveToken(ctx context.Context, clientID, clientSecret, tokenURL string, v url.Values, authStyle oauth2.AuthStyle) (*Token, error) {
	req, err := newTokenRequest(tokenURL, clientID, clientSecret, v, authStyle)
	if err != nil {
		return nil, err
	}
	token, err := doTokenRoundTrip(ctx, req)
	if err != nil {
		return nil, err
	}

	return token, err
}

func doTokenRoundTrip(ctx context.Context, req *http.Request) (*Token, error) {
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	failureStatus := r.StatusCode < 200 || r.StatusCode > 299
	retrieveError := &oauth2.RetrieveError{
		Response: r,
		Body:     body,
		// attempt to populate error detail below
	}

	var token *Token
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		// some endpoints return a query string
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			if failureStatus {
				return nil, retrieveError
			}
			return nil, fmt.Errorf("oauth2: cannot parse response: %v", err)
		}
		retrieveError.ErrorCode = vals.Get("error")
		retrieveError.ErrorDescription = vals.Get("error_description")
		retrieveError.ErrorURI = vals.Get("error_uri")
		token = &Token{
			AccessToken:  vals.Get("access_token"),
			TokenType:    vals.Get("token_type"),
			RefreshToken: vals.Get("refresh_token"),
			Raw:          vals,
		}
		e := vals.Get("expires_in")
		expires, _ := strconv.Atoi(e)
		if expires != 0 {
			token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
		}
	default:
		var tj tokenJSON
		if err = json.Unmarshal(body, &tj); err != nil {
			if failureStatus {
				return nil, retrieveError
			}
			return nil, fmt.Errorf("oauth2: cannot parse json: %v", err)
		}
		retrieveError.ErrorCode = tj.ErrorCode
		retrieveError.ErrorDescription = tj.ErrorDescription
		retrieveError.ErrorURI = tj.ErrorURI
		token = &Token{
			AccessToken:  tj.AccessToken,
			TokenType:    tj.TokenType,
			RefreshToken: tj.RefreshToken,
			Expiry:       tj.expiry(),
			Raw:          make(map[string]interface{}),
		}
		err = json.Unmarshal(body, &token.Raw) // no error checks for optional fields
		if err != nil {
			return nil, err
		}
	}
	// according to spec, servers should respond status 400 in error case
	// https://www.rfc-editor.org/rfc/rfc6749#section-5.2
	// but some unorthodox servers respond 200 in error case
	if failureStatus || retrieveError.ErrorCode != "" {
		return nil, retrieveError
	}
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	return token, nil
}
