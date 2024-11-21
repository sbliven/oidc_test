package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func openBrowser(url string) error {
	// Open url in a browser
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

func generateRandomString(length int) (string, error) {
	// Generate a random byte slice with the specified length
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Convert the byte slice to a base64-encoded string
	str := base64.RawURLEncoding.EncodeToString(bytes)

	// Trim any trailing padding characters from the string
	str = strings.TrimRight(str, "=")

	return str, nil
}

func setupOAuth2Config(ctx context.Context, clientID, clientSecret, issuerURL, redirectURI string) (*oidc.Provider, oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, oauth2.Config{}, fmt.Errorf("failed to create OIDC provider: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	return provider, oauth2Config, nil
}

func handleCallback(ctx context.Context, provider *oidc.Provider, oauth2Config oauth2.Config, clientID string, shutdown chan struct{}) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		fmt.Printf("Got Callback: %s %s\n", request.Method, request.URL)

		code := request.URL.Query().Get("code")
		token, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			fmt.Printf("Failed to exchange OAuth2 code for token: %v\n", err)
			return
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
		idToken, err := verifier.Verify(ctx, token.Extra("id_token").(string))
		if err != nil {
			fmt.Printf("Failed to verify ID token: %v\n", err)
			return
		} else {
			fmt.Printf("Verified ID token successfully\n")
		}

		claims := map[string]interface{}{}
		if err := idToken.Claims(&claims); err != nil {
			fmt.Printf("Failed to get ID token claims: %v\n", err)
			return
		}

		fmt.Printf("ID Token Claims:\n")
		for k, v := range claims {
			fmt.Printf("%s: %v\n", k, v)
		}

		fmt.Fprint(response, "<!DOCTYPE html><html><head><title>Authorization successful</title></head>"+
			"<body><h1>Authorization Successful</h1><p>You may close this window.</p></body></html>")

		go func() { shutdown <- struct{}{} }()
	}
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

	redirectURI := fmt.Sprintf("http://localhost:%d/auth", port)

	ctx := context.Background()
	provider, oauth2Config, err := setupOAuth2Config(ctx, clientID, clientSecret, issuerURL, redirectURI)
	if err != nil {
		panic(err)
	}

	url := oauth2Config.AuthCodeURL("state")
	fmt.Printf("Opening browser for authorization: %v\n", url)
	go openBrowser(url)

	server := &http.Server{Addr: fmt.Sprintf(":%v", port)}
	shutdown := make(chan struct{})

	http.HandleFunc("/auth", handleCallback(ctx, provider, oauth2Config, clientID, shutdown))

	// Start the HTTP server
	go func() {
		fmt.Printf("Listening on http://localhost:%v\n", port)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Error with webserver: %v\n", err)
		}
	}()

	<-shutdown

	// Shutdown the server
	if err := server.Shutdown(context.Background()); err != nil {
		fmt.Printf("Error during server shutdown: %v\n", err)
	}

}
