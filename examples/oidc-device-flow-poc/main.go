// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type providerMetadata struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorMessage string `json:"error_description"`
}

func main() {
	issuerURL := flag.String("issuer-url", "", "OIDC issuer URL")
	clientID := flag.String("client-id", "", "OIDC client ID")
	scopes := flag.String("scopes", "openid profile email offline_access", "OIDC scopes")
	timeout := flag.Duration("timeout", 5*time.Minute, "maximum time to poll for tokens")
	flag.Parse()

	if *issuerURL == "" || *clientID == "" {
		fmt.Println("usage: go run ./examples/oidc-device-flow-poc --issuer-url <issuer> --client-id <client>")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	metadata, err := discoverProvider(ctx, *issuerURL)
	if err != nil {
		fmt.Printf("discovery failed: %v\n", err)
		return
	}

	device, err := requestDeviceCode(ctx, metadata.DeviceAuthorizationEndpoint, *clientID, *scopes)
	if err != nil {
		fmt.Printf("device authorization failed: %v\n", err)
		return
	}

	printInstructions(device)

	tokens, err := pollTokenEndpoint(ctx, metadata.TokenEndpoint, *clientID, device)
	if err != nil {
		fmt.Printf("token polling failed: %v\n", err)
		return
	}

	fmt.Println("Login succeeded")
	fmt.Printf("token_type: %s\n", tokens.TokenType)
	fmt.Printf("expires_in: %ds\n", tokens.ExpiresIn)
	fmt.Printf("access_token: %s\n", summarizeToken(tokens.AccessToken))
	fmt.Printf("refresh_token: %s\n", summarizeToken(tokens.RefreshToken))
	fmt.Printf("id_token: %s\n", summarizeToken(tokens.IDToken))
}

func discoverProvider(ctx context.Context, issuer string) (providerMetadata, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	var metadata providerMetadata
	if err := getJSON(ctx, discoveryURL, &metadata); err != nil {
		return metadata, err
	}
	if metadata.DeviceAuthorizationEndpoint == "" {
		return metadata, errors.New("provider metadata does not include device_authorization_endpoint")
	}
	if metadata.TokenEndpoint == "" {
		return metadata, errors.New("provider metadata does not include token_endpoint")
	}
	return metadata, nil
}

func requestDeviceCode(ctx context.Context, endpoint, clientID, scopes string) (deviceAuthorizationResponse, error) {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("scope", scopes)

	var device deviceAuthorizationResponse
	if err := postFormJSON(ctx, endpoint, values, &device); err != nil {
		return device, err
	}
	if device.DeviceCode == "" || device.UserCode == "" || device.VerificationURI == "" {
		return device, errors.New("device authorization response is missing required fields")
	}
	if device.Interval <= 0 {
		device.Interval = 5
	}
	return device, nil
}

func pollTokenEndpoint(ctx context.Context, endpoint, clientID string, device deviceAuthorizationResponse) (tokenResponse, error) {
	interval := time.Duration(device.Interval) * time.Second

	for {
		select {
		case <-ctx.Done():
			return tokenResponse{}, ctx.Err()
		case <-time.After(interval):
		}

		values := url.Values{}
		values.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		values.Set("device_code", device.DeviceCode)
		values.Set("client_id", clientID)

		tokens, err := postTokenRequest(ctx, endpoint, values)
		if err != nil {
			return tokens, err
		}

		switch tokens.Error {
		case "":
			if tokens.AccessToken == "" {
				return tokens, errors.New("token endpoint returned success without access_token")
			}
			return tokens, nil
		case "authorization_pending":
			fmt.Println("Waiting for user authorization...")
			continue
		case "slow_down":
			interval += 5 * time.Second
			fmt.Printf("Provider requested slower polling; new interval is %s\n", interval)
			continue
		case "access_denied", "expired_token":
			return tokens, fmt.Errorf("%s: %s", tokens.Error, tokens.ErrorMessage)
		default:
			return tokens, fmt.Errorf("%s: %s", tokens.Error, tokens.ErrorMessage)
		}
	}
}

func getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return decodeResponse(resp, out)
}

func postFormJSON(ctx context.Context, endpoint string, values url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return decodeResponse(resp, out)
}

func postTokenRequest(ctx context.Context, endpoint string, values url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenResponse{}, err
	}
	if len(body) == 0 {
		return tokenResponse{}, fmt.Errorf("empty response body from %s", resp.Request.URL)
	}

	var tokens tokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return tokens, fmt.Errorf("decode response from %s: %w", resp.Request.URL, err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if tokens.Error != "" {
			return tokens, nil
		}
		return tokens, fmt.Errorf("request to %s failed with status %d: %s", resp.Request.URL, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return tokens, nil
}

func decodeResponse(resp *http.Response, out any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("empty response body from %s", resp.Request.URL)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response from %s: %w", resp.Request.URL, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("request to %s failed with status %d: %s", resp.Request.URL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func printInstructions(device deviceAuthorizationResponse) {
	fmt.Println("Harbor CLI SSO proof of concept")
	fmt.Printf("Open: %s\n", device.VerificationURI)
	if device.VerificationURIComplete != "" {
		fmt.Printf("Direct URL: %s\n", device.VerificationURIComplete)
	}
	fmt.Printf("Code: %s\n", device.UserCode)
	fmt.Printf("Expires in: %ds\n", device.ExpiresIn)
	fmt.Println("Waiting for authorization...")
}

func summarizeToken(token string) string {
	if token == "" {
		return "<not returned>"
	}
	if len(token) <= 12 {
		return "<redacted>"
	}
	return token[:6] + "..." + token[len(token)-6:]
}
