package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func open(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

func main() {
	// Get the client ID and client secret from environment variables
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	issuerURL := os.Getenv("OIDC_ISSUER")
	if issuerURL == "" {
		issuerURL = "https://morgana-kc.psi.ch/auth/realms/master"
	}
	var port int
	port, err := strconv.Atoi(os.Getenv("OIDC_PORT"))
	if err != nil {
		port = 18546
	}

	if clientID == "" || clientSecret == "" || issuerURL == "" {
		fmt.Println("OIDC_CLIENT_ID and/or OIDC_CLIENT_SECRET environment variables not set")
		return
	}

	// Replace these with your actual values
	redirectURI := fmt.Sprintf("http://localhost:%d/auth", port)

	// Create a new OIDC verifier using the issuer URL
	ctx := context.Background()
	fmt.Printf("Configuring OpenId provider from %v for authorization code flow\n", issuerURL)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		fmt.Printf("Failed to create OIDC provider: %v\n", err)
		return
	}

	// Create a new OAuth2 config using the client ID, client secret, and redirect URI
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	// Create a new HTTP handler that handles the OAuth2 callback and exchanges the authorization code for an access token
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		token, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			fmt.Printf("Failed to exchange OAuth2 code for token: %v\n", err)
			return
		}

		// Create a new ID token verifier using the OIDC provider
		verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

		// Verify the ID token in the access token
		idToken, err := verifier.Verify(ctx, token.Extra("id_token").(string))
		if err != nil {
			fmt.Printf("Failed to verify ID token: %v\n", err)
			return
		}

		// Get the user's email address from the ID token claims
		claims := map[string]interface{}{}
		if err := idToken.Claims(&claims); err != nil {
			fmt.Printf("Failed to get ID token claims: %v\n", err)
			return
		}
		name, ok := claims["preferred_username"].(string)
		if !ok {
			fmt.Println("preferred_username claim not found or has wrong type")
			return
		}

		// Print the user's info
		fmt.Printf("Username: %v\n", name)

		html := "<!DOCTYPE html>" +
			"<html><head><title>Authorization successful</title></head>" +
			"<body><h1>Authorization Successful</h1>" +
			"<p>You may close this window.</p>" +
			"</body></html>"
		fmt.Fprint(w, html)
	})

	// Authenticate user
	url := oauth2Config.AuthCodeURL("state")
	fmt.Printf("Opening browser for authorization: %v\n", url)
	go open(url)

	// Start the HTTP server
	fmt.Printf("Listening on http://localhost:%v\n", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil); err != nil {
		fmt.Printf("Failed to start HTTP server: %v\n", err)
	}

}
