package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wag"
	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
)

func init() {
	var err error
	platformKP, err = keys.GenerateECKeyPair()
	if err != nil {
		panic(err)
	}
	asKP, err = keys.GenerateECKeyPair()
	if err != nil {
		panic(err)
	}
	witIssuer = wit.NewIssuer(platformIssuer, platformKP.Private, witTTL)
	wagIssuer = wag.NewPlatformIssuer(platformIssuer, platformKP.Private, 0)
	authServer = wag.NewAuthorizationServer(asIssuer, asKP.Private, 0)
	_ = authServer.RegisterPlatform(wag.PlatformRegistration{
		IssuerID:  platformIssuer,
		PublicKey: platformKP.Public,
	})
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handleHealth(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestWITIssue_MissingSpiffeID(t *testing.T) {
	body := `{"workload_pub_jwk":{}}`
	req := httptest.NewRequest(http.MethodPost, "/wit/issue", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleWITIssue(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestWITIssue_Valid(t *testing.T) {
	workloadKP, _ := keys.GenerateECKeyPair()
	jwk, err := keys.PublicKeyToJWK(workloadKP.Public, "test-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]interface{}{
		"spiffe_id":        "spiffe://finclear.io/workload/test",
		"workload_pub_jwk": jwk,
	})
	req := httptest.NewRequest(http.MethodPost, "/wit/issue", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleWITIssue(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["wit"] == "" {
		t.Fatal("expected non-empty wit token")
	}
}

func TestWAGIssue_Valid(t *testing.T) {
	b := `{"spiffe_id":"spiffe://finclear.io/workload/test","scope":"fraud:read"}`
	req := httptest.NewRequest(http.MethodPost, "/wag/issue", strings.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleWAGIssue(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["grant"] == "" {
		t.Fatal("expected non-empty grant")
	}
}

func TestWAGIssue_MissingSpiffeID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/wag/issue", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleWAGIssue(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestToken_RoundTrip(t *testing.T) {
	// Issue a WAG grant, then exchange it.
	grant, err := wagIssuer.Issue(wag.GrantOptions{
		Subject:  "spiffe://finclear.io/workload/test",
		Audience: asIssuer,
		Scope:    "fraud:read",
	})
	if err != nil {
		t.Fatal(err)
	}

	form := "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + grant + "&scope=fraud:read"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["access_token"] == "" {
		t.Fatal("expected non-empty access_token")
	}
}

func TestToken_WrongGrantType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleToken(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestToken_ReplayRejected(t *testing.T) {
	grant, _ := wagIssuer.Issue(wag.GrantOptions{
		Subject:  "spiffe://finclear.io/workload/replay-test",
		Audience: asIssuer,
	})
	form := "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + grant
	exchange := func() int {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handleToken(rec, req)
		return rec.Code
	}
	if exchange() != http.StatusOK {
		t.Fatal("first exchange should succeed")
	}
	if exchange() != http.StatusUnauthorized {
		t.Fatal("second exchange (replay) should be rejected")
	}
}

func TestSPIREJWKS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handleSPIREJWKS(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var jwks map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&jwks)
	ks, _ := jwks["keys"].([]interface{})
	if len(ks) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}
}

func TestJWTParts(t *testing.T) {
	kp, _ := keys.GenerateECKeyPair()
	issuer := wit.NewIssuer("https://test.example", kp.Private, time.Minute)
	workloadKP, _ := keys.GenerateECKeyPair()
	token, err := issuer.Issue(wit.IssueOptions{
		Subject:     "spiffe://test.example/workload/x",
		Audiences:   []string{"https://as.example"},
		WorkloadKey: workloadKP.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := jwtParts(token)
	if parts["header"] == nil || parts["payload"] == nil {
		t.Fatal("expected decoded header and payload")
	}
}

func TestCORS_Preflight(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	req := httptest.NewRequest(http.MethodOptions, "/healthz", nil)
	rec := httptest.NewRecorder()
	cors(mux).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("expected CORS header")
	}
}
