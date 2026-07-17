package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

type proxy struct {
	publicKey ed25519.PublicKey
	transport *http.Transport
	dialer    net.Dialer
	mu        sync.Mutex
	nonces    map[string]int64
}

type authorizationClaims struct {
	Version   int    `json:"version"`
	Target    string `json:"target"`
	IssuedAt  int64  `json:"issuedAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Nonce     string `json:"nonce"`
}

func newProxy(publicKey ed25519.PublicKey) *proxy {
	return &proxy{
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		nonces:    make(map[string]int64),
		transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
		dialer: net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" && !r.URL.IsAbs() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	if !p.authorized(r) {
		w.Header().Set("Proxy-Authenticate", `Pandemonium realm="pandemonium-proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	started := time.Now()
	destination := requestDestination(r)
	status := http.StatusBadGateway
	var bytes int64
	if r.Method == http.MethodConnect {
		status, bytes = p.connect(w, r)
	} else {
		status, bytes = p.forward(w, r)
	}
	log.Printf("method=%s destination=%s status=%d bytes=%d duration_ms=%d", r.Method, destination, status, bytes, time.Since(started).Milliseconds())
}

func (p *proxy) authorized(r *http.Request) bool {
	value := r.Header.Get("Proxy-Authorization")
	scheme, token, ok := strings.Cut(value, " ")
	if !ok || scheme != "Pandemonium" {
		return false
	}
	payload, signature, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !ed25519.Verify(p.publicKey, []byte(payload), signatureBytes) {
		return false
	}
	var claims authorizationClaims
	if json.Unmarshal(payloadBytes, &claims) != nil || claims.Version != 1 || claims.Nonce == "" {
		return false
	}
	now := time.Now().Unix()
	if claims.IssuedAt < now-30 || claims.IssuedAt > now+30 || claims.ExpiresAt < now || claims.ExpiresAt > now+90 {
		return false
	}
	if claims.Target != requestDestination(r) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for nonce, expiry := range p.nonces {
		if expiry < now {
			delete(p.nonces, nonce)
		}
	}
	if _, used := p.nonces[claims.Nonce]; used {
		return false
	}
	p.nonces[claims.Nonce] = claims.ExpiresAt
	return true
}

func (p *proxy) forward(w http.ResponseWriter, r *http.Request) (int, int64) {
	if !r.URL.IsAbs() || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
		http.Error(w, "absolute http or https URL required", http.StatusBadRequest)
		return http.StatusBadRequest, 0
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopHeaders(out.Header)
	response, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return http.StatusBadGateway, 0
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	n, _ := io.Copy(w, response.Body)
	return response.StatusCode, n
}

func (p *proxy) connect(w http.ResponseWriter, r *http.Request) (int, int64) {
	upstream, err := p.dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return http.StatusBadGateway, 0
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "connection tunneling unavailable", http.StatusInternalServerError)
		return http.StatusInternalServerError, 0
	}
	client, buffer, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return http.StatusInternalServerError, 0
	}
	defer client.Close()
	defer upstream.Close()
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return http.StatusBadGateway, 0
	}
	if err := buffer.Flush(); err != nil {
		return http.StatusBadGateway, 0
	}
	if buffer.Reader.Buffered() > 0 {
		if _, err := io.CopyN(upstream, buffer, int64(buffer.Reader.Buffered())); err != nil {
			return http.StatusBadGateway, 0
		}
	}
	type copyResult struct{ n int64 }
	results := make(chan copyResult, 2)
	go func() { n, _ := io.Copy(upstream, client); results <- copyResult{n: n} }()
	go func() { n, _ := io.Copy(client, upstream); results <- copyResult{n: n} }()
	first := <-results
	_ = client.SetDeadline(time.Now())
	_ = upstream.SetDeadline(time.Now())
	second := <-results
	return http.StatusOK, first.n + second.n
}

func requestDestination(r *http.Request) string {
	if r.Method == http.MethodConnect {
		return r.Host
	}
	if _, _, err := net.SplitHostPort(r.URL.Host); err == nil {
		return r.URL.Host
	}
	port := "80"
	if r.URL.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(r.URL.Hostname(), port)
}

func removeHopHeaders(headers http.Header) {
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopHeaders {
		headers.Del(name)
	}
}

func copyHeaders(destination, source http.Header) {
	for key, values := range source {
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func main() {
	listen := strings.TrimSpace(os.Getenv("PANDEMONIUM_PROXY_LISTEN"))
	if listen == "" {
		listen = "127.0.0.1:3128"
	}
	publicKeyPath := strings.TrimSpace(os.Getenv("PANDEMONIUM_PROXY_PUBLIC_KEY_PATH"))
	if publicKeyPath == "" {
		log.Fatal("PANDEMONIUM_PROXY_PUBLIC_KEY_PATH is required")
	}
	publicKey, err := readPublicKey(publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           newProxy(publicKey),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-stop.Done()
		ctx, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("shutdown_error=%q", err.Error())
		}
	}()
	log.Printf("listening=%s", listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(fmt.Errorf("listen: %w", err))
	}
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read proxy public key: %w", err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("proxy public key must be PEM encoded")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse proxy public key: %w", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("proxy public key must be Ed25519")
	}
	return publicKey, nil
}
