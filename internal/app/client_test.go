package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &Client{
		AppID:   "123456",
		Signer:  &PEMSigner{key: key},
		BaseURL: server.URL,
		HTTP:    server.Client(),
	}, server
}

func TestCreateTokenSendsScopedRequest(t *testing.T) {
	var gotPath, gotAuth, gotVersion string
	var gotBody map[string]any

	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)

		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"token":"ghs_example","expires_at":"2026-08-07T12:00:00Z",
			"repository_selection":"selected","permissions":{"contents":"read"},
			"repositories":[{"name":"widget","full_name":"asw101/widget","private":true}]}`)
	}))

	token, err := client.CreateToken(context.Background(), 42, TokenRequest{
		Repositories: []string{"widget"},
		Permissions:  map[string]string{"contents": "read"},
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if want := "/app/installations/42/access_tokens"; gotPath != want {
		t.Errorf("got path %q, want %q", gotPath, want)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") || strings.Count(gotAuth, ".") != 2 {
		t.Errorf("got Authorization %q, want a Bearer JWT", gotAuth)
	}
	if gotVersion != "2022-11-28" {
		t.Errorf("got API version %q, want 2022-11-28", gotVersion)
	}
	if repos, _ := gotBody["repositories"].([]any); len(repos) != 1 || repos[0] != "widget" {
		t.Errorf("got repositories %v, want [widget]", gotBody["repositories"])
	}
	if token.Token != "ghs_example" {
		t.Errorf("got token %q, want ghs_example", token.Token)
	}
	if want := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC); !token.ExpiresAt.Equal(want) {
		t.Errorf("got expiry %s, want %s", token.ExpiresAt, want)
	}
	if len(token.Repositories) != 1 || token.Repositories[0].FullName != "asw101/widget" {
		t.Errorf("got repositories %+v", token.Repositories)
	}
}

func TestCreateTokenOmitsEmptyScope(t *testing.T) {
	var gotBody map[string]any
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"token":"ghs_example"}`)
	}))

	if _, err := client.CreateToken(context.Background(), 42, TokenRequest{}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, present := gotBody["repositories"]; present {
		t.Error("empty repositories should be omitted, not sent as null")
	}
	if _, present := gotBody["permissions"]; present {
		t.Error("empty permissions should be omitted, not sent as null")
	}
}

func TestAPIErrorCarriesMessage(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, `{"message":"There is at least one repository that does not exist"}`)
	}))

	_, err := client.CreateToken(context.Background(), 42, TokenRequest{Repositories: []string{"nope"}})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %v, want *APIError", err)
	}
	if apiErr.Status != http.StatusUnprocessableEntity {
		t.Errorf("got status %d, want 422", apiErr.Status)
	}
	if !strings.Contains(apiErr.Error(), "does not exist") {
		t.Errorf("got %q, want the API message", apiErr.Error())
	}
}

func TestInstallationForRepoExplainsNotFound(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}))

	_, err := client.InstallationForRepo(context.Background(), "asw101", "widget")
	if err == nil || !strings.Contains(err.Error(), "not installed on asw101/widget") {
		t.Fatalf("got %v, want an installation hint", err)
	}
}

func TestInstallationForRepoReturnsID(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/repos/asw101/widget/installation"; r.URL.Path != want {
			t.Errorf("got path %q, want %q", r.URL.Path, want)
		}
		fmt.Fprint(w, `{"id":99,"account":{"login":"asw101","type":"User"},"repository_selection":"selected"}`)
	}))

	installation, err := client.InstallationForRepo(context.Background(), "asw101", "widget")
	if err != nil {
		t.Fatalf("InstallationForRepo: %v", err)
	}
	if installation.ID != 99 || installation.Account.Login != "asw101" {
		t.Errorf("got %+v", installation)
	}
}

func TestInstallationsPaginates(t *testing.T) {
	var pages []string
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		if page == "1" {
			w.Write([]byte("["))
			for i := range 100 {
				if i > 0 {
					w.Write([]byte(","))
				}
				fmt.Fprintf(w, `{"id":%d}`, i+1)
			}
			w.Write([]byte("]"))
			return
		}
		fmt.Fprint(w, `[{"id":101}]`)
	}))

	installations, err := client.Installations(context.Background())
	if err != nil {
		t.Fatalf("Installations: %v", err)
	}
	if len(installations) != 101 {
		t.Errorf("got %d installations, want 101", len(installations))
	}
	if len(pages) != 2 || pages[0] != "1" || pages[1] != "2" {
		t.Errorf("got pages %v, want [1 2]", pages)
	}
}

func TestBaseURLTrimsTrailingSlash(t *testing.T) {
	client := &Client{BaseURL: "https://ghe.example.com/api/v3/"}
	if got := client.baseURL(); got != "https://ghe.example.com/api/v3" {
		t.Errorf("got %q, want the slash trimmed", got)
	}
	if got := (&Client{}).baseURL(); got != DefaultBaseURL {
		t.Errorf("got %q, want %q", got, DefaultBaseURL)
	}
}
