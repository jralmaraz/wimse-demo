// Workload service: transaction-processor (port 8083).
// Demonstrates the full WIMSE flow: WIT issuance → WAG exchange → WPT-protected API calls.
// POST /transaction/run triggers the end-to-end flow and returns a step trace.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wpt"
)

const (
	defaultAddr   = ":8083"
	workloadSPIFFE = "spiffe://finclear.io/workload/transaction-processor"
	workloadScope = "fraud:read compliance:write"
)

var workloadKP *keys.ECKeyPair

func main() {
	var err error
	workloadKP, err = keys.GenerateECKeyPair()
	must("workload key", err)

	addr := envOr("ADDR", defaultAddr)
	log.Printf("transaction-processor on %s", addr)

	mux := http.NewServeMux()
	mux.HandleFunc("/transaction/run", handleRun)
	mux.HandleFunc("/healthz", handleHealth)
	must("listen", http.ListenAndServe(addr, cors(mux)))
}

// POST /transaction/run — orchestrates the full WIMSE flow.
// Returns a structured step-by-step trace for the SPA to render.
func handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Amount   float64 `json:"amount"`
		Currency string  `json:"currency"`
		Merchant string  `json:"merchant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Amount = 1500.00
		req.Currency = "EUR"
		req.Merchant = "AcmeCorp Ltd"
	}

	spireURL  := envOr("SPIRE_URL", "http://localhost:8081")
	asURL     := envOr("AS_URL", "http://localhost:8082")
	fraudURL  := envOr("FRAUD_API_URL", "http://localhost:8084")
	compURL   := envOr("COMPLIANCE_API_URL", "http://localhost:8085")

	trace := &flowTrace{}

	// ── Step 1: publish workload public key as JWK ────────────────────────────
	pub := workloadKP.Public
	jwk, err := keys.PublicKeyToJWK(pub, "workload-1")
	if err != nil {
		jsonErr(w, fmt.Errorf("jwk: %w", err), http.StatusInternalServerError)
		return
	}
	trace.add("key_ready", "Workload generates EC P-256 key pair — public key will be bound into WIT", map[string]interface{}{
		"spiffe_id": workloadSPIFFE,
		"key_type":  "EC P-256",
		"use":       "sig",
	})

	// ── Step 2: request WIT from SPIRE ───────────────────────────────────────
	witResp, err := postJSON(spireURL+"/wit/issue", map[string]interface{}{
		"spiffe_id":       workloadSPIFFE,
		"workload_pub_jwk": jwk,
		"audiences":       []string{asURL},
	})
	if err != nil {
		jsonErr(w, fmt.Errorf("WIT issue: %w", err), http.StatusBadGateway)
		return
	}
	witToken, _ := witResp["wit"].(string)
	trace.add("wit_issued", "SPIRE issued a Workload Identity Token (wit+jwt) — SPIFFE ID bound to workload's public key", witResp)

	// ── Step 3: request WAG grant from SPIRE ─────────────────────────────────
	wagResp, err := postJSON(spireURL+"/wag/issue", map[string]interface{}{
		"spiffe_id": workloadSPIFFE,
		"scope":     workloadScope,
	})
	if err != nil {
		jsonErr(w, fmt.Errorf("WAG issue: %w", err), http.StatusBadGateway)
		return
	}
	wagGrant, _ := wagResp["grant"].(string)
	trace.add("wag_grant_issued", "SPIRE issued a Workload Authorization Grant (wag+jwt) — no per-workload AS registration needed", wagResp)

	// ── Step 4: exchange WAG at AS for access token ───────────────────────────
	formVals := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {wagGrant},
		"scope":      {workloadScope},
	}
	atResp, err := postForm(asURL+"/token", formVals)
	if err != nil {
		jsonErr(w, fmt.Errorf("token exchange: %w", err), http.StatusBadGateway)
		return
	}
	accessToken, _ := atResp["access_token"].(string)
	trace.add("access_token_issued", "Authorization Server verified the WAG grant and issued a scoped Bearer token (at+jwt)", atResp)

	// ── Step 5: call Fraud API with WPT proof ────────────────────────────────
	fraudTarget := fraudURL + "/fraud/score"
	proof, err := mintWPTProof(workloadKP.Private, witToken, fraudTarget)
	if err != nil {
		jsonErr(w, fmt.Errorf("WPT proof: %w", err), http.StatusInternalServerError)
		return
	}
	fraudBody, _ := json.Marshal(map[string]interface{}{
		"amount": req.Amount, "currency": req.Currency, "merchant": req.Merchant,
	})
	fraudResp, err := callAPI(fraudTarget, accessToken, proof, fraudBody)
	if err != nil {
		jsonErr(w, fmt.Errorf("fraud API: %w", err), http.StatusBadGateway)
		return
	}
	trace.add("fraud_checked", "Cross-cloud call to Fraud API (AWS) — Bearer token + WPT proof validates identity and binds request to target URI", fraudResp)

	// ── Step 6: call Compliance Reporter ─────────────────────────────────────
	compTarget := compURL + "/compliance/log"
	proof2, err := mintWPTProof(workloadKP.Private, witToken, compTarget)
	if err != nil {
		jsonErr(w, fmt.Errorf("WPT proof 2: %w", err), http.StatusInternalServerError)
		return
	}
	compBody, _ := json.Marshal(map[string]interface{}{
		"spiffe_id": workloadSPIFFE,
		"amount":    req.Amount,
		"currency":  req.Currency,
		"merchant":  req.Merchant,
		"fraud_result": fraudResp,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	})
	compResp, err := callAPI(compTarget, accessToken, proof2, compBody)
	if err != nil {
		jsonErr(w, fmt.Errorf("compliance API: %w", err), http.StatusBadGateway)
		return
	}
	trace.add("compliance_logged", "Cross-cloud call to Compliance Reporter (Azure) — full audit trail with cryptographic identity chain", compResp)

	jsonOK(w, map[string]interface{}{
		"ok":    true,
		"steps": trace.steps,
		"summary": map[string]interface{}{
			"workload":    workloadSPIFFE,
			"amount":      fmt.Sprintf("%.2f %s", req.Amount, req.Currency),
			"merchant":    req.Merchant,
			"fraud_score": fraudResp["score"],
			"logged":      compResp["logged"],
		},
	})
}

// mintWPTProof creates a WPT (DPoP-style proof) binding the WIT to the target URI.
func mintWPTProof(priv *ecdsa.PrivateKey, witToken, targetURI string) (string, error) {
	return wpt.Generate(wpt.GenerateOptions{
		WIT:         witToken,
		TargetURI:   targetURI,
		WorkloadKey: priv,
	})
}

func callAPI(target, bearer, proof string, body []byte) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("WPT", proof)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w (status %d)", err, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error %d: %v", resp.StatusCode, result["error"])
	}
	return result, nil
}

func postJSON(target string, body interface{}) (map[string]interface{}, error) {
	b, _ := json.Marshal(body)
	resp, err := http.Post(target, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("error %d: %v", resp.StatusCode, result["error"])
	}
	return result, nil
}

func postForm(target string, vals url.Values) (map[string]interface{}, error) {
	resp, err := http.Post(target, "application/x-www-form-urlencoded", strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("error %d: %v", resp.StatusCode, result["error"])
	}
	return result, nil
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok", "service": "transaction-processor"})
}

type flowStep struct {
	ID      string      `json:"id"`
	Label   string      `json:"label"`
	Payload interface{} `json:"payload"`
}

type flowTrace struct {
	steps []flowStep
}

func (t *flowTrace) add(id, label string, payload interface{}) {
	t.steps = append(t.steps, flowStep{ID: id, Label: label, Payload: payload})
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
