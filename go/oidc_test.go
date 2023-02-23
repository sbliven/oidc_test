package main

import (
    "context"
    "fmt"
    "net/http"

    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)

func main() {
    // Replace these with your actual values
    clientID := "your-client-id"
    clientSecret := "your-client-secret"
    redirectURI := "http://localhost:8080/callback"
    issuerURL := "https://accounts.google.com"

    // Create a new OIDC verifier using the issuer URL
    ctx := context.Background()
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
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
    }

    // Create a new HTTP handler that starts the OAuth2 flow
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        url := oauth2Config.AuthCodeURL("state")
        http.Redirect(w, r, url, http.StatusFound)
    })

    // Create a new HTTP handler that handles the OAuth2 callback and exchanges the authorization code for an access token
    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
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

        // Print the user's email address
        fmt.Printf("Email: %v\n", idToken.Claims["email"])
    })

    // Start the HTTP server
    fmt.Println("Listening on http://localhost:8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        fmt.Printf("Failed to start HTTP server: %v\n", err)
    }
}

