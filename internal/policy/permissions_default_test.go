package policy

import "testing"

func TestGrantWithoutPermissionsCoversAnUnrestrictedRequest(t *testing.T) {
	// A grant that names no permissions defers to the App's own set, so a
	// client need not name them either.
	g := Grant{Repos: []string{"_components", "_cloud_native_ai"}}

	if !g.Covers(Scope{Repos: []string{"_components"}}) {
		t.Error("want an unrestricted request to be covered")
	}
	if !g.Covers(Scope{Repos: []string{"_components"}, Permissions: map[string]string{"contents": "write"}}) {
		t.Error("want an explicit request to be covered too")
	}
	// It still cannot reach a repository outside the grant.
	if g.Covers(Scope{Repos: []string{"other"}}) {
		t.Error("repository scoping must still apply")
	}
}
