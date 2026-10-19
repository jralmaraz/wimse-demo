// Platform service: SPIRE simulator (port 8081) + Authorization Server (port 8082).
// Consolidated into one binary for Fly.io free-tier (3 VM limit); see README.
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wag"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
)

const (
	defaultAddr    = ":8081"
	platformIssuer = "https://spire.finclear.io"
	asIssuer       = "https://as.finclear.io"
	witTTL         = 10 * time.Minute
)

var (
	platformKP *keys.ECKeyPair
	asKP       *keys.ECKeyPair
	witIssuer  *wit.Issuer
	wagIssuer  *wag.PlatformIssuer
	authServer *wag.AuthorizationServer
)

func main() {
	var err error
	platformKP, err = keys.GenerateECKeyPair()
	must("platform key", err)
	asKP, err = keys.GenerateECKeyPair()
	must("as key", err)

	witIssuer = wit.NewIssuer(platformIssuer, platformKP.Private, witTTL)
	wagIssuer = wag.NewPlatformIssuer(platformIssuer, platformKP.Private, 0)

	authServer = wag.NewAuthorizationServer(asIssuer, asKP.Private, 0)
	must("register platform", authServer.RegisterPlatform(wag.PlatformRegistration{
		IssuerID:  platformIssuer,
		PublicKey: platformKP.Public,
	}))

	addr := envOr("ADDR", defaultAddr)
	log.Printf("platform (SPIRE sim + AS) on %s", addr)

	mux := http.NewServeMux()
	mux.HandleFunc("/wit/issue", handleWITIssue)
	mux.HandleFunc("/wag/issue", handleWAGIssue)
	mux.HandleFunc("/token", handleToken)
	// /.well-known/jwks.json serves the AS public key — used by resource servers to validate at+jwt.
	mux.HandleFunc("/.well-known/jwks.json", handleASJWKS)
	// /spire/jwks.json serves the platform key — used to verify WIT and WAG signatures.
	mux.HandleFunc("/spire/jwks.json", handleSPIREJWKS)
	mux.HandleFunc("/healthz", handleHealth)
	must("platform listen", http.ListenAndServe(addr, cors(mux)))
}

// POST /wit/issue — issues a WIT for the requesting workload.
// Body: {"spiffe_id":"spiffe://finclear.io/workload/transaction-processor","workload_pub_jwk":{...}}
func handleWITIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SpiffeID     string     `json:"spiffe_id"`
		WorkloadPub  *keys.JWK  `json:"workload_pub_jwk"`
		Audiences    []string   `json:"audiences"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SpiffeID == "" || req.WorkloadPub == nil {
		http.Error(w, "bad request: need spiffe_id and workload_pub_jwk", http.StatusBadRequest)
		return
	}
	pub, err := keys.JWKToPublicKey(req.WorkloadPub) //nolint:staticcheck
	if err != nil {
		jsonErr(w, fmt.Errorf("invalid workload key: %w", err), http.StatusBadRequest)
		return
	}
	auds := req.Audiences
	if len(auds) == 0 {
		auds = []string{asIssuer}
	}
	token, err := witIssuer.Issue(wit.IssueOptions{
		Subject:     req.SpiffeID,
		Audiences:   auds,
		WorkloadKey: pub,
	})
	if err != nil {
		jsonErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"wit":    token,
		"parts":  jwtParts(token),
		"issuer": platformIssuer,
	})
}

// POST /wag/issue — issues a WAG grant for a workload identified by SPIFFE ID.
// Body: {"spiffe_id":"...","scope":"fraud:read compliance:write"}
func handleWAGIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SpiffeID string `json:"spiffe_id"`
		Scope    string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SpiffeID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	grant, err := wagIssuer.Issue(wag.GrantOptions{
		Subject:  req.SpiffeID,
		Audience: asIssuer,
		Scope:    req.Scope,
	})
	if err != nil {
		jsonErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"grant":           grant,
		"parts":           jwtParts(grant),
		"platform_issuer": platformIssuer,
		"as_audience":     asIssuer,
	})
}

// GET /.well-known/jwks.json — SPIRE platform JWKS.
func handleSPIREJWKS(w http.ResponseWriter, r *http.Request) {
	serveJWKS(w, platformKP.Public)
}

// POST /token — WAG token exchange (RFC 7523 jwt-bearer grant).
// Form: grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<wag+jwt>&scope=...
func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		jsonErr(w, errors.New("unsupported_grant_type"), http.StatusBadRequest)
		return
	}
	assertion := r.FormValue("assertion")
	if assertion == "" {
		jsonErr(w, errors.New("missing assertion"), http.StatusBadRequest)
		return
	}
	resp, err := authServer.Exchange(assertion, r.FormValue("scope"))
	if err != nil {
		jsonErr(w, err, http.StatusUnauthorized)
		return
	}
	jsonOK(w, map[string]interface{}{
		"access_token": resp.AccessToken,
		"token_type":   resp.TokenType,
		"expires_in":   resp.ExpiresIn,
		"scope":        resp.Scope,
		"parts":        jwtParts(resp.AccessToken),
	})
}

// GET /.well-known/jwks.json — AS JWKS for resource servers to validate at+jwt.
func handleASJWKS(w http.ResponseWriter, r *http.Request) {
	serveJWKS(w, asKP.Public)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok"})
}

func serveJWKS(w http.ResponseWriter, pub *ecdsa.PublicKey) {
	jwk, err := keys.PublicKeyToJWK(pub, "1")
	if err != nil {
		jsonErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"keys": []interface{}{jwk}})
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// jwtParts splits a compact JWT for display — header/payload decoded, signature truncated.
func jwtParts(token string) map[string]interface{} {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return map[string]interface{}{"raw": token}
	}
	decode := func(s string) interface{} {
		b, err := jwt.NewParser().DecodeSegment(s)
		if err != nil {
			return s
		}
		var v interface{}
		if err := json.Unmarshal(b, &v); err != nil {
			return string(b)
		}
		return v
	}
	sigPreview := parts[2]
	if len(sigPreview) > 8 {
		sigPreview = sigPreview[:8] + "…"
	}
	return map[string]interface{}{
		"header":    decode(parts[0]),
		"payload":   decode(parts[1]),
		"signature": sigPreview,
		"compact":   token,
	}
}

func must(label string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
