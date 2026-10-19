package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wag"
)

// testAS sets up a mock AS that the apis service fetches its JWKS from.
func testAS(t *testing.T) (*httptest.Server, *keys.ECKeyPair) {
	t.Helper()
	asKP, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwk, _ := keys.PublicKeyToJWK(asKP.Public, "test-1")
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{jwk}})
	})
	srv := httptest.NewServer(mux)
	t.Setenv("AS_URL", srv.URL)
	// reset cache so this test's AS is used
	cachedPubMu.Lock()
	cachedPub = nil
	cachedPubMu.Unlock()
	return srv, asKP
}

func mintAccessToken(t *testing.T, asKP *keys.ECKeyPair, sub, scope string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   asIssuer,
		"sub":   sub,
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
		"scope": scope,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "at+jwt"
	signed, err := tok.SignedString(asKP.Private)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return signed
}

func TestFraudScore_Unauthorized_NoBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/fraud/score", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handleFraudScore(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestFraudScore_Valid_LowRisk(t *testing.T) {
	srv, asKP := testAS(t)
	defer srv.Close()

	token := mintAccessToken(t, asKP, "spiffe://finclear.io/workload/transaction-processor", "fraud:read")
	body := `{"amount":500,"currency":"EUR","merchant":"AcmeCorp"}`
	req := httptest.NewRequest(http.MethodPost, "/fraud/score", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleFraudScore(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["risk"] != "low" {
		t.Fatalf("expected low risk, got %v", resp["risk"])
	}
	if resp["sub"] != "spiffe://finclear.io/workload/transaction-processor" {
		t.Fatalf("expected SPIFFE sub, got %v", resp["sub"])
	}
}

func TestFraudScore_Valid_HighRisk(t *testing.T) {
	srv, asKP := testAS(t)
	defer srv.Close()

	token := mintAccessToken(t, asKP, "spiffe://finclear.io/workload/transaction-processor", "fraud:read")
	body := `{"amount":15000,"currency":"EUR","merchant":"BigCorp"}`
	req := httptest.NewRequest(http.MethodPost, "/fraud/score", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleFraudScore(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["risk"] != "high" {
		t.Fatalf("expected high risk, got %v", resp["risk"])
	}
}

func TestComplianceLog_Valid(t *testing.T) {
	srv, asKP := testAS(t)
	defer srv.Close()

	token := mintAccessToken(t, asKP, "spiffe://finclear.io/workload/transaction-processor", "compliance:write")
	body := `{"amount":500,"merchant":"AcmeCorp"}`
	req := httptest.NewRequest(http.MethodPost, "/compliance/log", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handleComplianceLog(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["logged"] != true {
		t.Fatal("expected logged=true")
	}
	if resp["audit_id"] == "" {
		t.Fatal("expected non-empty audit_id")
	}
}

func TestComplianceLog_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/compliance/log", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handleComplianceLog(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestComplianceLog_InvalidToken(t *testing.T) {
	srv, _ := testAS(t)
	defer srv.Close()

	req := httptest.NewRequest(http.MethodPost, "/compliance/log", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer not.a.token")
	rec := httptest.NewRecorder()
	handleComplianceLog(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestComplianceLog_ExpiredToken(t *testing.T) {
	srv, asKP := testAS(t)
	defer srv.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": asIssuer,
		"sub": "spiffe://finclear.io/workload/test",
		"iat": now.Add(-2 * time.Hour).Unix(),
		"exp": now.Add(-1 * time.Hour).Unix(), // already expired
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "at+jwt"
	signed, _ := tok.SignedString(asKP.Private)

	req := httptest.NewRequest(http.MethodPost, "/compliance/log", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	handleComplianceLog(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", rec.Code)
	}
}

func TestComplianceLog_WrongIssuer(t *testing.T) {
	srv, asKP := testAS(t)
	defer srv.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://rogue.example",
		"sub": "spiffe://finclear.io/workload/test",
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "at+jwt"
	signed, _ := tok.SignedString(asKP.Private)

	req := httptest.NewRequest(http.MethodPost, "/compliance/log", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	handleComplianceLog(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong issuer, got %d", rec.Code)
	}
}

func TestFraudScore_WrongSigningKey(t *testing.T) {
	srv, _ := testAS(t)
	defer srv.Close()

	// Sign with a different key — not registered in the mock AS JWKS.
	rogueKP, _ := keys.GenerateECKeyPair()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": asIssuer,
		"sub": "spiffe://finclear.io/workload/rogue",
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "at+jwt"
	signed, _ := tok.SignedString(rogueKP.Private)

	req := httptest.NewRequest(http.MethodPost, "/fraud/score", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	handleFraudScore(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong signing key, got %d", rec.Code)
	}
}

func TestFraudScoreFunction(t *testing.T) {
	cases := []struct {
		amount   float64
		wantRisk string
	}{
		{500, "low"},
		{5001, "medium"},
		{10001, "high"},
	}
	for _, c := range cases {
		_, risk := fraudScore(c.amount)
		if risk != c.wantRisk {
			t.Errorf("amount %.0f: expected %s, got %s", c.amount, c.wantRisk, risk)
		}
	}
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handleHealth("fraud-api")(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// TestJWKSCache verifies that the cached key is used on the second call.
func TestJWKSCache(t *testing.T) {
	srv, asKP := testAS(t)
	defer srv.Close()

	p1, err := getASPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := getASPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	// Both pointers should be the same cached instance.
	if p1 != p2 {
		t.Error("expected second call to return cached key pointer")
	}
	_ = asKP
}

// TestWAGGrantUsedDirectlyIsRejected verifies that a raw WAG grant is not accepted as a Bearer token.
func TestWAGGrantUsedDirectlyIsRejected(t *testing.T) {
	srv, _ := testAS(t)
	defer srv.Close()

	// Issue a real WAG grant (wag+jwt) and try to use it as a Bearer token — must fail typ check.
	platKP, _ := keys.GenerateECKeyPair()
	wagIssuer := wag.NewPlatformIssuer("https://spire.finclear.io", platKP.Private, 0)
	grant, _ := wagIssuer.Issue(wag.GrantOptions{
		Subject:  "spiffe://finclear.io/workload/test",
		Audience: "https://as.finclear.io",
		Scope:    "fraud:read",
	})

	req := httptest.NewRequest(http.MethodPost, "/fraud/score", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+grant)
	rec := httptest.NewRecorder()
	handleFraudScore(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401: WAG grant must not be accepted as Bearer, got %d", rec.Code)
	}
}
