// APIs service: fraud-api (port 8084) + compliance-reporter (port 8085).
// Consolidated into one binary for Fly.io free-tier (3 VM limit); see README.
// Both validate the Bearer at+jwt against the AS JWKS before serving.
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
)

const (
	defaultFraudAddr      = ":8084"
	defaultComplianceAddr = ":8085"
	asIssuer              = "https://as.finclear.io"
	jwksCacheTTL          = 5 * time.Minute
)

// jwksCache caches the AS public key to avoid fetching on every request.
var (
	cachedPub     *ecdsa.PublicKey
	cachedPubAt   time.Time
	cachedPubMu   sync.Mutex
)

func main() {
	fraudAddr := envOr("FRAUD_ADDR", defaultFraudAddr)
	compAddr := envOr("COMPLIANCE_ADDR", defaultComplianceAddr)
	log.Printf("fraud-api on %s | compliance-reporter on %s", fraudAddr, compAddr)

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/fraud/score", handleFraudScore)
		mux.HandleFunc("/healthz", handleHealth("fraud-api"))
		must("fraud listen", http.ListenAndServe(fraudAddr, cors(mux)))
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/compliance/log", handleComplianceLog)
	mux.HandleFunc("/healthz", handleHealth("compliance-reporter"))
	must("compliance listen", http.ListenAndServe(compAddr, cors(mux)))
}

// POST /fraud/score — validates Bearer token, returns a deterministic fraud score.
func handleFraudScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, err := validateBearer(r)
	if err != nil {
		jsonErr(w, fmt.Errorf("unauthorized: %w", err), http.StatusUnauthorized)
		return
	}

	var req struct {
		Amount   float64 `json:"amount"`
		Currency string  `json:"currency"`
		Merchant string  `json:"merchant"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	score, risk := fraudScore(req.Amount)
	jsonOK(w, map[string]interface{}{
		"score":       score,
		"risk":        risk,
		"checked_by":  "fraud-api (AWS / us-east-1)",
		"sub":         claims.Subject,
		"amount":      req.Amount,
		"currency":    req.Currency,
		"merchant":    req.Merchant,
		"verified_at": time.Now().UTC().Format(time.RFC3339),
		"note":        "Bearer token verified against AS JWKS — caller identity is cryptographically confirmed",
	})
}

// POST /compliance/log — validates Bearer token, records audit entry.
func handleComplianceLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, err := validateBearer(r)
	if err != nil {
		jsonErr(w, fmt.Errorf("unauthorized: %w", err), http.StatusUnauthorized)
		return
	}

	var payload map[string]interface{}
	json.NewDecoder(r.Body).Decode(&payload)

	auditID := fmt.Sprintf("AUDIT-%06d", rand.Intn(999999))
	jsonOK(w, map[string]interface{}{
		"logged":    true,
		"audit_id":  auditID,
		"logged_by": "compliance-reporter (Azure / westeurope)",
		"sub":       claims.Subject,
		"payload":   payload,
		"logged_at": time.Now().UTC().Format(time.RFC3339),
		"note":      "Audit entry logged — sub is SPIFFE ID from verified Bearer token; identity chain is cryptographic",
	})
}

// validateBearer parses and validates the Bearer at+jwt in the Authorization header.
func validateBearer(r *http.Request) (*jwt.RegisteredClaims, error) {
	authHdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHdr, "Bearer ") {
		return nil, fmt.Errorf("missing Bearer token")
	}
	tokenStr := strings.TrimPrefix(authHdr, "Bearer ")

	pub, err := getASPublicKey()
	if err != nil {
		return nil, fmt.Errorf("fetch AS key: %w", err)
	}

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])
			}
			if t.Header["typ"] != "at+jwt" {
				return nil, fmt.Errorf("unexpected typ: %v", t.Header["typ"])
			}
			return pub, nil
		},
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(asIssuer),
	)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	return claims, nil
}

// getASPublicKey fetches the first EC key from the AS JWKS, cached for 5 minutes.
func getASPublicKey() (*ecdsa.PublicKey, error) {
	cachedPubMu.Lock()
	defer cachedPubMu.Unlock()

	if cachedPub != nil && time.Since(cachedPubAt) < jwksCacheTTL {
		return cachedPub, nil
	}

	asURL := envOr("AS_URL", "http://localhost:8082")
	resp, err := http.Get(asURL + "/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body struct {
		Keys []keys.JWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if len(body.Keys) == 0 {
		return nil, fmt.Errorf("empty JWKS")
	}

	pub, err := keys.JWKToPublicKey(&body.Keys[0])
	if err != nil {
		return nil, fmt.Errorf("parse JWK: %w", err)
	}

	cachedPub = pub
	cachedPubAt = time.Now()
	return pub, nil
}

func fraudScore(amount float64) (float64, string) {
	switch {
	case amount > 10000:
		return 88.0, "high"
	case amount > 5000:
		return 67.0, "medium"
	default:
		return 12.0, "low"
	}
}

func handleHealth(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]string{"status": "ok", "service": name})
	}
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, WPT")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
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
