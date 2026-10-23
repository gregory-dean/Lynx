package verify

import (
	"context"
	"net/http"
	"time"

	"github.com/gregory-dean/lynx/internal/config"
	"github.com/gregory-dean/lynx/internal/scanner"
)

// Verifier can optionally check whether a secret is live.
type Verifier interface {
	CanVerify(ruleID string) bool
	Verify(ctx context.Context, match string) (bool, error)
}

// Registry holds available verifiers.
type Registry struct {
	verifiers []Verifier
	client    *http.Client
}

// NewRegistry creates a registry with built-in verifiers.
func NewRegistry(client *http.Client) *Registry {
	if client == nil {
		client = &http.Client{Timeout: config.VerifyTimeout}
	}
	return &Registry{
		client: client,
		verifiers: []Verifier{
			&GitHubVerifier{Client: client},
		},
	}
}

// Apply runs verification on findings in place for supported rule IDs.
// On verifier errors, Verified is left unset (nil) so failures are not
// reported as confirmed-invalid secrets.
func (r *Registry) Apply(ctx context.Context, findings []scanner.Finding) {
	for i := range findings {
		f := &findings[i]
		if f.Severity != "high" {
			continue
		}
		for _, v := range r.verifiers {
			if !v.CanVerify(f.RuleID) {
				continue
			}
			vctx, cancel := context.WithTimeout(ctx, config.VerifyTimeout)
			ok, err := v.Verify(vctx, f.Match)
			cancel()
			if err != nil {
				break
			}
			verified := ok
			f.Verified = &verified
			break
		}
	}
}

// GitHubVerifier checks PATs via GET /user.
type GitHubVerifier struct {
	Client    *http.Client
	Endpoint  string // override for tests
}

func (v *GitHubVerifier) CanVerify(ruleID string) bool {
	return ruleID == "github-pat"
}

func (v *GitHubVerifier) Verify(ctx context.Context, match string) (bool, error) {
	endpoint := v.Endpoint
	if endpoint == "" {
		endpoint = "https://api.github.com/user"
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+match)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "lynx-secret-scanner")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}
