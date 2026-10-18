package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
)

func TestMain(m *testing.M) {
	var err error
	workloadKP, err = keys.GenerateECKeyPair()
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// startPlatformMock wires up a minimal platform+APIs mock so workload tests
// exercise the full handleRun logic without a real network.
func startPlatformMock(t *testing.T) (spireURL, asURL, fraudURL, compURL string) {
	t.Helper()

	// SPIRE: /wit/issue and /wag/issue
	spireMux := http.NewServeMux()
	spireMux.HandleFunc("/wit/issue", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"wit":     "header.payload.sig",
			"issuer":  "https://spire.finclear.io",
			"parts": map[string]interface{}{
				"header":    map[string]interface{}{"alg": "ES256", "typ": "wit+jwt"},
				"payload":   map[string]interface{}{"sub": "spiffe://finclear.io/workload/transaction-processor"},
				"signature": "truncatedsig",
			},
		})
	})
	spireMux.HandleFunc("/wag/issue", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"grant":  "header.payload.sig",
			"issuer": "https://spire.finclear.io",
			"parts": map[string]interface{}{
				"header":    map[string]interface{}{"alg": "ES256", "typ": "wag+jwt"},
				"payload":   map[string]interface{}{"sub": "spiffe://finclear.io/workload/transaction-processor", "jti": "abc123"},
				"signature": "truncatedsig",
			},
		})
	})
	spireServer := httptest.NewServer(spireMux)
	t.Cleanup(spireServer.Close)

	// AS: /token
	asMux := http.NewServeMux()
	asMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "header.payload.sig",
			"token_type":   "Bearer",
			"expires_in":   300,
			"parts": map[string]interface{}{
				"header":    map[string]interface{}{"alg": "ES256", "typ": "at+jwt"},
				"payload":   map[string]interface{}{"sub": "spiffe://finclear.io/workload/transaction-processor"},
				"signature": "truncatedsig",
			},
		})
	})
	asServer := httptest.NewServer(asMux)
	t.Cleanup(asServer.Close)

	// Fraud API: /fraud/score
	fraudMux := http.NewServeMux()
	fraudMux.HandleFunc("/fraud/score", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "missing authorization"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"score":    12,
			"risk":     "low",
			"approved": true,
		})
	})
	fraudServer := httptest.NewServer(fraudMux)
	t.Cleanup(fraudServer.Close)

	// Compliance: /compliance/log
	compMux := http.NewServeMux()
	compMux.HandleFunc("/compliance/log", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "missing authorization"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"logged":    true,
			"record_id": "rec-test-001",
		})
	})
	compServer := httptest.NewServer(compMux)
	t.Cleanup(compServer.Close)

	return spireServer.URL, asServer.URL, fraudServer.URL, compServer.URL
}

func runRequest(t *testing.T, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/transaction/run", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRun(rr, req)
	return rr
}

func setEnv(t *testing.T, key, val string) {
	t.Helper()
	prev := os.Getenv(key)
	os.Setenv(key, val)
	t.Cleanup(func() { os.Setenv(key, prev) })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestTransaction_FullFlow(t *testing.T) {
	spire, as, fraud, comp := startPlatformMock(t)
	setEnv(t, "SPIRE_URL", spire)
	setEnv(t, "AS_URL", as)
	setEnv(t, "FRAUD_API_URL", fraud)
	setEnv(t, "COMPLIANCE_API_URL", comp)

	body := `{"amount":1500,"currency":"EUR","merchant":"AcmeCorp Ltd"}`
	rr := runRequest(t, strings.NewReader(body))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}
	steps, _ := resp["steps"].([]interface{})
	if len(steps) != 6 {
		t.Errorf("expected 6 steps, got %d", len(steps))
	}
	wantIDs := []string{"key_ready", "wit_issued", "wag_grant_issued", "access_token_issued", "fraud_checked", "compliance_logged"}
	for i, s := range steps {
		step := s.(map[string]interface{})
		if step["id"] != wantIDs[i] {
			t.Errorf("step %d: expected id=%q got %q", i, wantIDs[i], step["id"])
		}
	}
}

func TestTransaction_DefaultAmountOnBadJSON(t *testing.T) {
	spire, as, fraud, comp := startPlatformMock(t)
	setEnv(t, "SPIRE_URL", spire)
	setEnv(t, "AS_URL", as)
	setEnv(t, "FRAUD_API_URL", fraud)
	setEnv(t, "COMPLIANCE_API_URL", comp)

	// Malformed JSON falls back to defaults without 400
	rr := runRequest(t, strings.NewReader("{not json}"))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with fallback defaults, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTransaction_EmptyBody(t *testing.T) {
	spire, as, fraud, comp := startPlatformMock(t)
	setEnv(t, "SPIRE_URL", spire)
	setEnv(t, "AS_URL", as)
	setEnv(t, "FRAUD_API_URL", fraud)
	setEnv(t, "COMPLIANCE_API_URL", comp)

	rr := runRequest(t, bytes.NewReader(nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with empty body, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTransaction_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/transaction/run", nil)
	rr := httptest.NewRecorder()
	handleRun(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestTransaction_SPIREDown(t *testing.T) {
	setEnv(t, "SPIRE_URL", "http://127.0.0.1:19999") // nothing listening
	setEnv(t, "AS_URL", "http://127.0.0.1:19998")
	setEnv(t, "FRAUD_API_URL", "http://127.0.0.1:19997")
	setEnv(t, "COMPLIANCE_API_URL", "http://127.0.0.1:19996")

	body := `{"amount":100,"currency":"EUR","merchant":"test"}`
	rr := runRequest(t, strings.NewReader(body))
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502 when SPIRE is down, got %d", rr.Code)
	}
}

func TestTransaction_ASDown(t *testing.T) {
	spire, _, _, _ := startPlatformMock(t)
	setEnv(t, "SPIRE_URL", spire)
	setEnv(t, "AS_URL", "http://127.0.0.1:19998") // nothing listening
	setEnv(t, "FRAUD_API_URL", "http://127.0.0.1:19997")
	setEnv(t, "COMPLIANCE_API_URL", "http://127.0.0.1:19996")

	body := `{"amount":100,"currency":"EUR","merchant":"test"}`
	rr := runRequest(t, strings.NewReader(body))
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502 when AS is down, got %d", rr.Code)
	}
}

func TestTransaction_FraudAPIDown(t *testing.T) {
	spire, as, _, _ := startPlatformMock(t)
	setEnv(t, "SPIRE_URL", spire)
	setEnv(t, "AS_URL", as)
	setEnv(t, "FRAUD_API_URL", "http://127.0.0.1:19997") // nothing listening
	setEnv(t, "COMPLIANCE_API_URL", "http://127.0.0.1:19996")

	body := `{"amount":100,"currency":"EUR","merchant":"test"}`
	rr := runRequest(t, strings.NewReader(body))
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502 when fraud API is down, got %d", rr.Code)
	}
}

func TestTransaction_ComplianceAPIDown(t *testing.T) {
	spire, as, fraud, _ := startPlatformMock(t)
	setEnv(t, "SPIRE_URL", spire)
	setEnv(t, "AS_URL", as)
	setEnv(t, "FRAUD_API_URL", fraud)
	setEnv(t, "COMPLIANCE_API_URL", "http://127.0.0.1:19996") // nothing listening

	body := `{"amount":100,"currency":"EUR","merchant":"test"}`
	rr := runRequest(t, strings.NewReader(body))
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502 when compliance is down, got %d", rr.Code)
	}
}

func TestTransaction_SummaryFields(t *testing.T) {
	spire, as, fraud, comp := startPlatformMock(t)
	setEnv(t, "SPIRE_URL", spire)
	setEnv(t, "AS_URL", as)
	setEnv(t, "FRAUD_API_URL", fraud)
	setEnv(t, "COMPLIANCE_API_URL", comp)

	body := `{"amount":9999.50,"currency":"GBP","merchant":"GlobalPay"}`
	rr := runRequest(t, strings.NewReader(body))

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	summary, _ := resp["summary"].(map[string]interface{})

	if summary == nil {
		t.Fatal("expected summary field in response")
	}
	if !strings.Contains(summary["amount"].(string), "GBP") {
		t.Errorf("summary.amount should contain currency, got %q", summary["amount"])
	}
	if summary["merchant"] != "GlobalPay" {
		t.Errorf("summary.merchant: want GlobalPay, got %v", summary["merchant"])
	}
	if summary["workload"] != workloadSPIFFE {
		t.Errorf("summary.workload: want %q, got %v", workloadSPIFFE, summary["workload"])
	}
}

func TestTransaction_FraudAPIRejectsNoAuth(t *testing.T) {
	spire, as, _, comp := startPlatformMock(t)

	// Fraud API that always rejects missing auth
	strictFraud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}))
	t.Cleanup(strictFraud.Close)

	setEnv(t, "SPIRE_URL", spire)
	setEnv(t, "AS_URL", as)
	setEnv(t, "FRAUD_API_URL", strictFraud.URL)
	setEnv(t, "COMPLIANCE_API_URL", comp)

	body := `{"amount":100,"currency":"EUR","merchant":"test"}`
	rr := runRequest(t, strings.NewReader(body))
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502 when fraud API returns 401, got %d", rr.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", resp["status"])
	}
	if resp["service"] != "transaction-processor" {
		t.Errorf("expected service=transaction-processor, got %q", resp["service"])
	}
}
