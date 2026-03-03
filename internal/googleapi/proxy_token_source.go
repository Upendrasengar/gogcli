// proxy_token_source.go — Fetch access tokens from a remote proxy.
//
// When GOG_TOKEN_PROXY_URL is set, this TokenSource calls the platform
// proxy instead of using local client_id/client_secret + refresh_token.
// This keeps all OAuth secrets off the machine entirely.
//
// Expected env vars:
//   GOG_TOKEN_PROXY_URL  — e.g. https://api.myclawbots.ai/google/token
//   PROXY_API_KEY        — the proxy key for authentication (x-api-key header)
//
// The proxy returns: { "access_token": "ya29...", "expires_in": 3599 }

package googleapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// proxyTokenSource fetches access tokens from a remote proxy endpoint
// instead of exchanging credentials locally.
type proxyTokenSource struct {
	proxyURL string
	apiKey   string

	mu     sync.Mutex
	cached *oauth2.Token
}

type proxyTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

func (p *proxyTokenSource) Token() (*oauth2.Token, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Return cached token if still valid
	if p.cached != nil && p.cached.Valid() {
		return p.cached, nil
	}

	// Call the proxy endpoint
	req, err := http.NewRequest("POST", p.proxyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("proxy token source: create request: %w", err)
	}
	req.Header.Set("x-api-key", p.apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxy token source: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("proxy token source: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp proxyTokenResponse
		_ = json.Unmarshal(body, &errResp)
		detail := errResp.Detail
		if detail == "" {
			detail = errResp.Error
		}
		if detail == "" {
			detail = string(body)
		}
		return nil, fmt.Errorf("proxy token source: HTTP %d: %s", resp.StatusCode, detail)
	}

	var tokenResp proxyTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("proxy token source: parse response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("proxy token source: empty access_token in response")
	}

	// Cache the token with expiry (subtract 60s safety margin)
	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3599
	}
	expiry := time.Now().Add(time.Duration(expiresIn-60) * time.Second)

	p.cached = &oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		Expiry:      expiry,
	}

	return p.cached, nil
}
