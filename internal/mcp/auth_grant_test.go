// Copyright 2026 Koopa. All rights reserved.

package mcp

// auth_grant_test.go — regression tests for the token grant surface (MCP-SEC-1).
//
// Dynamic client registration is unauthenticated, so a client_credentials
// grant would let any caller able to reach /oauth/register mint MCP access
// tokens without the owner's Google authorization. The grant surface is
// therefore locked to:
//   - authorization_code + PKCE (owner-authorized via Google callback)
//   - refresh_token (rotation of owner-issued tokens)
//   - the static MCP_TOKEN accepted directly by BearerAuth
// client_credentials must be rejected as unsupported_grant_type even for a
// successfully registered client, over both form fields and HTTP Basic auth.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMetadata_GrantTypesExact(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", http.NoBody)
	w := httptest.NewRecorder()
	o.Metadata(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Metadata() status = %d, want %d", w.Code, http.StatusOK)
	}
	var meta struct {
		GrantTypes []string `json:"grant_types_supported"`
	}
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("Metadata() decode error: %v", err)
	}
	want := []string{"authorization_code", "refresh_token"}
	if diff := cmp.Diff(want, meta.GrantTypes); diff != "" {
		t.Errorf("Metadata() grant_types_supported mismatch (-want +got):\n%s", diff)
	}
}

func TestToken_ClientCredentials_Unsupported(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	cid, csec := registerClient(t, o)

	tests := []struct {
		name     string
		clientID string
		secret   string
		basic    bool
	}{
		{name: "valid credentials via form", clientID: cid, secret: csec},
		{name: "valid credentials via basic auth", clientID: cid, secret: csec, basic: true},
		{name: "wrong secret", clientID: cid, secret: "wrong-secret"},
		{name: "unknown client_id", clientID: "unknown", secret: "any"},
		{name: "no credentials", clientID: "", secret: ""},
		{name: "SQL in client_id", clientID: "'; DROP TABLE clients;--", secret: "x"},
		{name: "null byte in client_id", clientID: cid + "\x00", secret: "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := url.Values{"grant_type": {"client_credentials"}}
			if !tt.basic {
				form.Set("client_id", tt.clientID)
				form.Set("client_secret", tt.secret)
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.basic {
				req.SetBasicAuth(tt.clientID, tt.secret)
			}
			w := httptest.NewRecorder()
			o.Token(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Token(client_credentials, %q) status = %d, want %d",
					tt.name, w.Code, http.StatusBadRequest)
			}
			var resp map[string]any
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Token(client_credentials, %q) decode error: %v", tt.name, err)
			}
			if resp["error"] != "unsupported_grant_type" {
				t.Errorf("Token(client_credentials, %q) error = %v, want %q",
					tt.name, resp["error"], "unsupported_grant_type")
			}
			if tok, ok := resp["access_token"]; ok {
				t.Errorf("Token(client_credentials, %q) minted access_token %v, want none", tt.name, tok)
			}
			if rt, ok := resp["refresh_token"]; ok {
				t.Errorf("Token(client_credentials, %q) minted refresh_token %v, want none", tt.name, rt)
			}
		})
	}
}

// TestToken_AuthorizationCodeFlow_MintsBearerToken pins the token exchange path:
// a registered client exchanges an authorization code with a valid PKCE
// verifier, the minted access token reaches the BearerAuth-protected handler,
// and the refresh token exchanges for another access token that does the same.
func TestToken_AuthorizationCodeFlow_MintsBearerToken(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	cid, csec := registerClient(t, o)

	verifier := "grant-surface-e2e-verifier-value"
	code := o.issueCode(pkceChallenge(verifier))

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cid},
		"client_secret": {csec},
		"code":          {code},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	o.Token(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Token(authorization_code) status = %d, want %d; body: %s",
			w.Code, http.StatusOK, w.Body.String())
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&tok); err != nil {
		t.Fatalf("Token(authorization_code) decode error: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("Token(authorization_code) = %+v, want non-empty access and refresh tokens", tok)
	}

	if got := bearerStatus(t, o, tok.AccessToken); got != http.StatusNoContent {
		t.Errorf("BearerAuth(authorization_code token) status = %d, want %d", got, http.StatusNoContent)
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	o.Token(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Token(refresh_token) status = %d, want %d; body: %s",
			w.Code, http.StatusOK, w.Body.String())
	}
	var refreshed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&refreshed); err != nil {
		t.Fatalf("Token(refresh_token) decode error: %v", err)
	}
	if got := bearerStatus(t, o, refreshed.AccessToken); got != http.StatusNoContent {
		t.Errorf("BearerAuth(refreshed token) status = %d, want %d", got, http.StatusNoContent)
	}
}

func TestBearerAuth_StaticTokenPreserved(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	if got := bearerStatus(t, o, "static-test-token"); got != http.StatusNoContent {
		t.Errorf("BearerAuth(static token) status = %d, want %d", got, http.StatusNoContent)
	}
}

// bearerStatus sends a request carrying the given bearer token through a
// BearerAuth-wrapped handler. The 204 sentinel proves the protected handler ran;
// httptest.ResponseRecorder starts at 200 before any handler writes a response.
func bearerStatus(t *testing.T, o *Provider, tok string) int {
	t.Helper()
	handler := BearerAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), o)
	req := httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}
