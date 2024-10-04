package sso

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
)

type KeycloakOAuthProvider struct {
	RedirectURI  string
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	Cancel       context.CancelFunc
}

func (g *KeycloakOAuthProvider) BuildAuthURL(state string) (string, error) {
	var opts []oauth2.AuthCodeOption

	return g.OAuth2Config.AuthCodeURL(state, opts...), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (g *KeycloakOAuthProvider) HandleCallback(r *http.Request) (identity *SSOIdentity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	token, err := g.OAuth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("keycloak: failed to get token: %v", err)
	}

	return g.createIdentity(r.Context(), token)
}

func (g *KeycloakOAuthProvider) createIdentity(ctx context.Context, token *oauth2.Token) (identity *SSOIdentity, err error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, errors.New("keycloak: no id_token in token response")
	}
	idToken, err := g.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return identity, fmt.Errorf("keycloak: failed to verify ID Token: %v", err)
	}

	var claims struct {
		Username string `json:"name"`
		Email    string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return identity, fmt.Errorf("oidc: failed to decode claims: %v", err)
	}

	identity = &SSOIdentity{
		UserID:        idToken.Subject,
		Username:      claims.Username,
		Email:         claims.Email,
		ConnectorData: []byte(token.RefreshToken),
	}

	return identity, nil
}

func Create(redirectUrl string) *KeycloakOAuthProvider {
	return &KeycloakOAuthProvider{
		RedirectURI: redirectUrl,
		OAuth2Config: &oauth2.Config{
			ClientID: "test",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://http://localhost:8081/auth/realms/test2/protocol/openid-connect/auth",
				TokenURL: "https://http://localhost:8081/auth/realms/test2/protocol/openid-connect/token",
			},
			RedirectURL: redirectUrl,
			Scopes:      []string{"openid", "profile", "email"},
		},
	}
}
