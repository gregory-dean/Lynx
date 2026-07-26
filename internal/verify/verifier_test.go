package verify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/direo/lynx/internal/scanner"
)

func TestGitHubVerifierInvalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	v := &GitHubVerifier{
		Client:   srv.Client(),
		Endpoint: srv.URL,
	}
	ok, err := v.Verify(context.Background(), "ghp_abcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected invalid token to return false")
	}
}

func TestGitHubVerifierValidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"test"}`))
	}))
	defer srv.Close()

	v := &GitHubVerifier{
		Client:   srv.Client(),
		Endpoint: srv.URL,
	}
	ok, err := v.Verify(context.Background(), "ghp_abcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected valid token")
	}
}

func TestRegistryApply(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	reg := &Registry{
		client: srv.Client(),
		verifiers: []Verifier{
			&GitHubVerifier{Client: srv.Client(), Endpoint: srv.URL},
		},
	}
	findings := []scanner.Finding{
		{RuleID: "github-pat", Severity: "high", Match: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{RuleID: "jwt-token", Severity: "medium", Match: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.xxxx"},
	}
	reg.Apply(context.Background(), findings)
	if findings[0].Verified == nil || *findings[0].Verified {
		t.Fatalf("github verified=%v", findings[0].Verified)
	}
	if findings[1].Verified != nil {
		t.Fatal("medium severity should skip verify")
	}
}

func TestRegistryApplyLeavesNilOnError(t *testing.T) {
	reg := &Registry{
		verifiers: []Verifier{
			&errVerifier{},
		},
	}
	findings := []scanner.Finding{
		{RuleID: "github-pat", Severity: "high", Match: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
	}
	reg.Apply(context.Background(), findings)
	if findings[0].Verified != nil {
		t.Fatalf("expected nil Verified on error, got %v", *findings[0].Verified)
	}
}

func TestNewRegistryAndCanVerify(t *testing.T) {
	reg := NewRegistry(nil)
	if reg == nil || len(reg.verifiers) != 1 {
		t.Fatal("expected GitHub verifier only")
	}
	gh := &GitHubVerifier{}
	if !gh.CanVerify("github-pat") || gh.CanVerify("aws-access-key") {
		t.Fatal("github CanVerify mismatch")
	}
}

type errVerifier struct{}

func (errVerifier) CanVerify(ruleID string) bool { return ruleID == "github-pat" }
func (errVerifier) Verify(context.Context, string) (bool, error) {
	return false, errors.New("network down")
}
