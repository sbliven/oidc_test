package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
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

/*
 * state is a random string of 48 bytes (64 base64url chars).
 * The verifier is a private random string of 96 bytes (128 base64url chars).
 * The challenge is the SHA256 hash of the verifier, base64url encoded.
 */
type pkceChallenge struct {
	state     string
	verifier  string
	challenge string
}

/*
 * Generate a PKCE code verifier and challenge.
 */
func generatePKCE() (pkceChallenge, error) {
	state, err := generateRandomString(48)
	if err != nil {
		return pkceChallenge{}, err
	}
	// Generate random verifier of 96 bytes (128 base64url chars)
	// Note this is stronger than oauth2GenerateVerifier
	// verifier, err := generateRandomString(96)
	// if err != nil {
	// 	return pkceChallenge{}, err
	// }
	verifier := oauth2.GenerateVerifier()

	// Create SHA256 hash of verifier
	h := sha256.New()
	h.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return pkceChallenge{state, verifier, challenge}, nil
}

func setupOAuth2Config(ctx context.Context, clientID, clientSecret, issuerURL, redirectURI string) (*oidc.Provider, oauth2.Config, pkceChallenge, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, oauth2.Config{}, pkceChallenge{}, fmt.Errorf("failed to create OIDC provider: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	pkce, err := generatePKCE()
	if err != nil {
		return nil, oauth2Config, pkceChallenge{}, err
	}
	fmt.Printf("❗️ Using PKCE with verifier: %v\n", pkce.verifier)
	return provider, oauth2Config, pkce, nil
}

func handleCallback(ctx context.Context, provider *oidc.Provider, oauth2Config oauth2.Config, clientID string, pkce pkceChallenge, shutdown chan struct{}) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		fmt.Printf("⬅️ Got Authorization Response: %s %s\n", request.Method, request.URL)
		fmt.Print(urlParams(request.URL))

		// Verify state
		responseState := request.FormValue("state")
		if responseState == "" {
			fmt.Printf("❌ No state in authorization response\n")
			return
		}
		if responseState != pkce.state {
			fmt.Printf("❌ State mismatch in authorization response\n")
			return
		} else {
			fmt.Printf("✅ State matched in authorization response\n")
		}

		code := request.URL.Query().Get("code")
		var oauthToken *oauth2.Token
		var err error
		fmt.Printf("↔️ Exchanging authorization code for OAuth2token\n")

		oauthToken, err = oauth2Config.Exchange(ctx, code,
			// oauth2.SetAuthURLParam("code_verifier", pkce.verifier),
			oauth2.VerifierOption(pkce.verifier),
			oauth2.AccessTypeOffline,
			oauth2.ApprovalForce,
		)
		if err != nil {
			fmt.Printf("❌ Failed to exchange OAuth2 code for token: %v\n", err)
			go func() { shutdown <- struct{}{} }()
			return
		}

		fmt.Printf("❗️ OAuth2 Access Token: %v\n", oauthToken.AccessToken)

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauthToken.Extra("id_token").(string)
		if !ok {
			fmt.Print("❌ OAuth2 Access Token misses the OIDC id_token")
			go func() { shutdown <- struct{}{} }()
			return
		}
		fmt.Printf("❗️ OIDC ID Token: %v\n", rawIDToken)

		// Parse and verify ID Token payload.
		verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			fmt.Printf("❌ Failed to verify OIDC token: %v\n", err)
			go func() { shutdown <- struct{}{} }()
			return
		} else {
			fmt.Printf("✅ Verified OIDC id token successfully\n")
		}

		claims := map[string]interface{}{}
		if err := idToken.Claims(&claims); err != nil {
			fmt.Printf("❌Failed to get ID token claims: %v\n", err)
			go func() { shutdown <- struct{}{} }()
			return
		}

		fmt.Printf("❗️ ID Token Claims:\n")
		for k, v := range claims {
			fmt.Printf("  %s: %v\n", k, v)
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
	var port int
	port, err := strconv.Atoi(os.Getenv("OIDC_PORT"))
	if err != nil {
		port = 18546
	}

	if clientID == "" || issuerURL == "" {
		fmt.Println("OIDC_CLIENT_ID or OIDC_ISSUER environment variables not set")
		return
	}

	redirectURI := fmt.Sprintf("http://localhost:%d/auth", port)

	fmt.Printf("➡️ Building Authorization Request\n")
	ctx := context.Background()
	provider, oauth2Config, pkce, err := setupOAuth2Config(ctx, clientID, clientSecret, issuerURL, redirectURI)
	if err != nil {
		panic(err)
	}

	var urlStr string
	if pkce.challenge != "" {
		urlStr = oauth2Config.AuthCodeURL(pkce.state,
			// oauth2.SetAuthURLParam("code_challenge", pkce.challenge),
			// oauth2.SetAuthURLParam("code_challenge_method", "S256")
			oauth2.S256ChallengeOption(pkce.verifier))
	} else {
		urlStr = oauth2Config.AuthCodeURL("state")
	}

	fmt.Printf("➡️ Opening browser for authorization: %v\n", urlStr)
	parsedURL, err := url.Parse(urlStr)
	if err == nil {
		fmt.Print(urlParams(parsedURL))
	}
	go openBrowser(urlStr)

	server := &http.Server{Addr: fmt.Sprintf(":%v", port)}
	shutdown := make(chan struct{})

	http.HandleFunc("/auth", handleCallback(ctx, provider, oauth2Config, clientID, pkce, shutdown))

	// Start the HTTP server
	go func() {
		fmt.Printf("❗️ Listening on http://localhost:%v\n", port)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("❌ Error with webserver: %v\n", err)
		}
	}()

	<-shutdown

	// Shutdown the server
	if err := server.Shutdown(context.Background()); err != nil {
		fmt.Printf("❌ Error during server shutdown: %v\n", err)
	}

}

func urlParams(parsedURL *url.URL) string {
	params := parsedURL.Query()
	var result string
	for key, values := range params {
		for _, value := range values {
			result += fmt.Sprintf("- %s: %s\n", key, value)
		}
	}
	return result
}
