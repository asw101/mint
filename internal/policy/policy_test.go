package policy

import "testing"

func TestGrantCoversRepos(t *testing.T) {
	tests := []struct {
		name  string
		grant Grant
		scope Scope
		want  bool
	}{
		{
			name:  "exact match",
			grant: Grant{Repos: []string{"one"}},
			scope: Scope{Repos: []string{"one"}},
			want:  true,
		},
		{
			name:  "subset is covered",
			grant: Grant{Repos: []string{"one", "two", "three"}},
			scope: Scope{Repos: []string{"two"}},
			want:  true,
		},
		{
			name:  "superset is not",
			grant: Grant{Repos: []string{"one"}},
			scope: Scope{Repos: []string{"one", "two"}},
			want:  false,
		},
		{
			name:  "wildcard covers anything",
			grant: Grant{Repos: []string{AllRepos}},
			scope: Scope{Repos: []string{"anything"}},
			want:  true,
		},
		{
			// Naming no repositories means the installation's whole reach, so
			// a finite grant must not satisfy it.
			name:  "unscoped request needs a wildcard",
			grant: Grant{Repos: []string{"one", "two"}},
			scope: Scope{},
			want:  false,
		},
		{
			name:  "unscoped request against wildcard",
			grant: Grant{Repos: []string{AllRepos}},
			scope: Scope{},
			want:  true,
		},
		{
			name:  "empty grant covers nothing",
			grant: Grant{},
			scope: Scope{Repos: []string{"one"}},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.grant.Covers(tc.scope); got != tc.want {
				t.Errorf("Covers() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGrantCoversPermissions(t *testing.T) {
	tests := []struct {
		name  string
		grant Grant
		scope Scope
		want  bool
	}{
		{
			name:  "read satisfied by write",
			grant: Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "write"}},
			scope: Scope{Repos: []string{"one"}, Permissions: map[string]string{"contents": "read"}},
			want:  true,
		},
		{
			name:  "write not satisfied by read",
			grant: Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "read"}},
			scope: Scope{Repos: []string{"one"}, Permissions: map[string]string{"contents": "write"}},
			want:  false,
		},
		{
			name:  "unlisted permission is refused",
			grant: Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "read"}},
			scope: Scope{Repos: []string{"one"}, Permissions: map[string]string{"issues": "read"}},
			want:  false,
		},
		{
			name:  "grant without permissions does not restrict them",
			grant: Grant{Repos: []string{"one"}},
			scope: Scope{Repos: []string{"one"}, Permissions: map[string]string{"contents": "write"}},
			want:  true,
		},
		{
			// Requesting no permissions inherits the installation's full set,
			// which a restricted grant cannot bound.
			name:  "restricted grant refuses an unrestricted request",
			grant: Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "read"}},
			scope: Scope{Repos: []string{"one"}},
			want:  false,
		},
		{
			name:  "case insensitive levels",
			grant: Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "WRITE"}},
			scope: Scope{Repos: []string{"one"}, Permissions: map[string]string{"contents": "Read"}},
			want:  true,
		},
		{
			// An unrecognised level must never be satisfied by a weaker grant.
			name:  "unknown level outranks everything",
			grant: Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "admin"}},
			scope: Scope{Repos: []string{"one"}, Permissions: map[string]string{"contents": "sudo"}},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.grant.Covers(tc.scope); got != tc.want {
				t.Errorf("Covers() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCoveredByAnyDoesNotCombineGrants(t *testing.T) {
	grants := []Grant{
		{Repos: []string{"one"}},
		{Repos: []string{"two"}},
	}
	// Each grant covers half the request. Neither was written to permit both,
	// so the union must not be inferred.
	if CoveredByAny(grants, Scope{Repos: []string{"one", "two"}}) {
		t.Error("grants were combined; a request must fit inside a single grant")
	}
	if !CoveredByAny(grants, Scope{Repos: []string{"two"}}) {
		t.Error("want the second grant to cover a request it fits")
	}
}

func TestScopeNormalize(t *testing.T) {
	got := Scope{Repos: []string{"two", "one", "two", "  ", " three "}}.Normalize()
	want := []string{"one", "three", "two"}
	if len(got.Repos) != len(want) {
		t.Fatalf("got %v, want %v", got.Repos, want)
	}
	for i := range want {
		if got.Repos[i] != want[i] {
			t.Fatalf("got %v, want %v", got.Repos, want)
		}
	}
}

func TestScopeString(t *testing.T) {
	tests := []struct {
		scope Scope
		want  string
	}{
		{Scope{}, "(unscoped)"},
		{Scope{Repos: []string{"b", "a"}}, "a,b"},
		{
			Scope{Repos: []string{"a"}, Permissions: map[string]string{"issues": "write", "contents": "read"}},
			"a contents:read,issues:write",
		},
	}
	for _, tc := range tests {
		if got := tc.scope.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

func TestScopeValidate(t *testing.T) {
	valid := []Scope{
		{Repos: []string{"one"}},
		{Repos: []string{"one"}, Permissions: map[string]string{"contents": "read"}},
		{},
	}
	for _, s := range valid {
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%v): %v", s, err)
		}
	}

	invalid := []Scope{
		{Repos: []string{"owner/name"}},
		{Repos: []string{" "}},
		{Permissions: map[string]string{"contents": "sudo"}},
		{Permissions: map[string]string{"": "read"}},
	}
	for _, s := range invalid {
		if err := s.Validate(); err == nil {
			t.Errorf("Validate(%v): want error", s)
		}
	}
}
