package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHealthAndAuthentication(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(newProxy(publicKey))
	defer server.Close()
	response, err := http.Get(server.URL + "/healthz")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("health response: status=%v error=%v", response.StatusCode, err)
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/not-health", nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("auth response: status=%v error=%v", response.StatusCode, err)
	}
}

func TestForwardsAuthenticatedHTTPAndStripsProxyAuthorization(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	var proxyAuthorization string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyAuthorization = r.Header.Get("Proxy-Authorization")
		w.Header().Set("X-Origin", "test")
		_, _ = io.WriteString(w, "forwarded")
	}))
	defer target.Close()
	proxyServer := httptest.NewServer(newProxy(publicKey))
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	request, _ := http.NewRequest(http.MethodGet, target.URL+"/private?token=never-log-this", nil)
	request.Header.Set("Proxy-Authorization", signedToken(t, privateKey, strings.TrimPrefix(target.URL, "http://")))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "forwarded" || proxyAuthorization != "" || response.Header.Get("X-Origin") != "test" {
		t.Fatalf("unexpected forward response body=%q proxyAuth=%q", body, proxyAuthorization)
	}
}

func TestAuthenticatedConnectTunnel(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		connection, acceptErr := echo.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()
	proxyServer := httptest.NewServer(newProxy(publicKey))
	defer proxyServer.Close()
	proxyAddress := strings.TrimPrefix(proxyServer.URL, "http://")
	connection, err := net.DialTimeout("tcp", proxyAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	auth := signedToken(t, privateKey, echo.Addr().String())
	_, _ = fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", echo.Addr(), echo.Addr(), auth)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("connect response: status=%v error=%v", response.StatusCode, err)
	}
	_, _ = connection.Write([]byte("ping"))
	payload := make([]byte, 4)
	if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != "ping" {
		t.Fatalf("tunnel payload=%q error=%v", payload, err)
	}
}

func TestRejectsReplayedOrWrongTargetAuthorization(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	proxyServer := httptest.NewServer(newProxy(publicKey))
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	token := signedToken(t, privateKey, strings.TrimPrefix(target.URL, "http://"))

	request, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	request.Header.Set("Proxy-Authorization", token)
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("first response: status=%v error=%v", response.StatusCode, err)
	}
	response.Body.Close()

	request, _ = http.NewRequest(http.MethodGet, target.URL, nil)
	request.Header.Set("Proxy-Authorization", token)
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("replay response: status=%v error=%v", response.StatusCode, err)
	}
	response.Body.Close()

	request, _ = http.NewRequest(http.MethodGet, target.URL, nil)
	request.Header.Set("Proxy-Authorization", signedToken(t, privateKey, "example.com:80"))
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("wrong-target response: status=%v error=%v", response.StatusCode, err)
	}
	response.Body.Close()
}

func TestRequestDestinationAddsDefaultPort(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "http://example.com/path", nil)
	if destination := requestDestination(request); destination != "example.com:80" {
		t.Fatalf("http destination=%q", destination)
	}
	request, _ = http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	if destination := requestDestination(request); destination != "example.com:443" {
		t.Fatalf("https destination=%q", destination)
	}
}

func signedToken(t *testing.T, privateKey ed25519.PrivateKey, target string) string {
	t.Helper()
	now := time.Now().Unix()
	payloadBytes, err := json.Marshal(authorizationClaims{Version: 1, Target: target, IssuedAt: now, ExpiresAt: now + 60, Nonce: fmt.Sprintf("nonce-%d", now)})
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := ed25519.Sign(privateKey, []byte(payload))
	return "Pandemonium " + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}
