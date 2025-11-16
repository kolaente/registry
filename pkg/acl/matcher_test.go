package acl

import (
	"reflect"
	"testing"

	"github.com/kolaente/registry/pkg/config"
)

func TestMatcher_GetAllowedActions(t *testing.T) {
	rules := []config.ACLRule{
		{Account: "admin", Name: "*", Actions: []string{"*"}},
		{Account: "developer", Name: "myorg/backend-*", Actions: []string{"pull", "push"}},
		{Account: "developer", Name: "myorg/frontend", Actions: []string{"pull"}},
		{Account: "readonly", Name: "myorg/*", Actions: []string{"pull"}},
		{Account: "*", Name: "public/*", Actions: []string{"pull"}},
	}

	matcher := NewMatcher(rules)

	tests := []struct {
		name       string
		account    string
		repository string
		want       []string
	}{
		{
			name:       "admin has all actions on any repo",
			account:    "admin",
			repository: "myorg/backend-api",
			want:       []string{"pull", "push", "delete"},
		},
		{
			name:       "developer can pull and push to backend-*",
			account:    "developer",
			repository: "myorg/backend-api",
			want:       []string{"pull", "push"},
		},
		{
			name:       "developer can only pull from frontend",
			account:    "developer",
			repository: "myorg/frontend",
			want:       []string{"pull"},
		},
		{
			name:       "developer has no access to non-matching repos",
			account:    "developer",
			repository: "myorg/other",
			want:       []string{},
		},
		{
			name:       "readonly can pull from myorg/*",
			account:    "readonly",
			repository: "myorg/anything",
			want:       []string{"pull"},
		},
		{
			name:       "wildcard account can pull from public/*",
			account:    "anyone",
			repository: "public/image",
			want:       []string{"pull"},
		},
		{
			name:       "no access to non-matching repository",
			account:    "unknown",
			repository: "private/repo",
			want:       []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matcher.GetAllowedActions(tt.account, tt.repository)

			// Convert slices to maps for comparison (order doesn't matter)
			gotMap := make(map[string]bool)
			for _, action := range got {
				gotMap[action] = true
			}
			wantMap := make(map[string]bool)
			for _, action := range tt.want {
				wantMap[action] = true
			}

			if !reflect.DeepEqual(gotMap, wantMap) {
				t.Errorf("GetAllowedActions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcher_HasAccess(t *testing.T) {
	rules := []config.ACLRule{
		{Account: "admin", Name: "*", Actions: []string{"*"}},
		{Account: "developer", Name: "myorg/backend-*", Actions: []string{"pull", "push"}},
		{Account: "developer", Name: "myorg/frontend", Actions: []string{"pull"}},
	}

	matcher := NewMatcher(rules)

	tests := []struct {
		name            string
		account         string
		repository      string
		requiredActions []string
		want            bool
	}{
		{
			name:            "admin has all access",
			account:         "admin",
			repository:      "any/repo",
			requiredActions: []string{"pull", "push", "delete"},
			want:            true,
		},
		{
			name:            "developer can pull and push to backend-*",
			account:         "developer",
			repository:      "myorg/backend-api",
			requiredActions: []string{"pull", "push"},
			want:            true,
		},
		{
			name:            "developer cannot delete from backend-*",
			account:         "developer",
			repository:      "myorg/backend-api",
			requiredActions: []string{"delete"},
			want:            false,
		},
		{
			name:            "developer can only pull from frontend",
			account:         "developer",
			repository:      "myorg/frontend",
			requiredActions: []string{"pull"},
			want:            true,
		},
		{
			name:            "developer cannot push to frontend",
			account:         "developer",
			repository:      "myorg/frontend",
			requiredActions: []string{"push"},
			want:            false,
		},
		{
			name:            "no access to non-matching repo",
			account:         "developer",
			repository:      "other/repo",
			requiredActions: []string{"pull"},
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.HasAccess(tt.account, tt.repository, tt.requiredActions); got != tt.want {
				t.Errorf("HasAccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcher_matchPattern(t *testing.T) {
	matcher := &Matcher{}

	tests := []struct {
		name       string
		pattern    string
		repository string
		want       bool
	}{
		{
			name:       "exact match",
			pattern:    "myorg/frontend",
			repository: "myorg/frontend",
			want:       true,
		},
		{
			name:       "wildcard matches all",
			pattern:    "*",
			repository: "any/repository",
			want:       true,
		},
		{
			name:       "prefix wildcard match",
			pattern:    "myorg/backend-*",
			repository: "myorg/backend-api",
			want:       true,
		},
		{
			name:       "prefix wildcard match multiple chars",
			pattern:    "myorg/backend-*",
			repository: "myorg/backend-service-v2",
			want:       true,
		},
		{
			name:       "prefix wildcard no match",
			pattern:    "myorg/backend-*",
			repository: "myorg/frontend",
			want:       false,
		},
		{
			name:       "directory wildcard match",
			pattern:    "myorg/*",
			repository: "myorg/anything",
			want:       true,
		},
		{
			name:       "directory wildcard no match",
			pattern:    "myorg/*",
			repository: "otherorg/anything",
			want:       false,
		},
		{
			name:       "single char wildcard match",
			pattern:    "myorg/app?",
			repository: "myorg/app1",
			want:       true,
		},
		{
			name:       "single char wildcard no match",
			pattern:    "myorg/app?",
			repository: "myorg/app12",
			want:       false,
		},
		{
			name:       "no match different name",
			pattern:    "myorg/frontend",
			repository: "myorg/backend",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.matchPattern(tt.pattern, tt.repository); got != tt.want {
				t.Errorf("matchPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseScope(t *testing.T) {
	tests := []struct {
		name             string
		scope            string
		wantResourceType string
		wantName         string
		wantActions      []string
	}{
		{
			name:             "valid scope with multiple actions",
			scope:            "repository:myorg/app:pull,push",
			wantResourceType: "repository",
			wantName:         "myorg/app",
			wantActions:      []string{"pull", "push"},
		},
		{
			name:             "valid scope with single action",
			scope:            "repository:myorg/app:pull",
			wantResourceType: "repository",
			wantName:         "myorg/app",
			wantActions:      []string{"pull"},
		},
		{
			name:             "invalid scope - too few parts",
			scope:            "repository:myorg/app",
			wantResourceType: "",
			wantName:         "",
			wantActions:      nil,
		},
		{
			name:             "invalid scope - empty",
			scope:            "",
			wantResourceType: "",
			wantName:         "",
			wantActions:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResourceType, gotName, gotActions := ParseScope(tt.scope)
			if gotResourceType != tt.wantResourceType {
				t.Errorf("ParseScope() resourceType = %v, want %v", gotResourceType, tt.wantResourceType)
			}
			if gotName != tt.wantName {
				t.Errorf("ParseScope() name = %v, want %v", gotName, tt.wantName)
			}
			if !reflect.DeepEqual(gotActions, tt.wantActions) {
				t.Errorf("ParseScope() actions = %v, want %v", gotActions, tt.wantActions)
			}
		})
	}
}

func TestFormatScope(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		repoName     string
		actions      []string
		want         string
	}{
		{
			name:         "multiple actions",
			resourceType: "repository",
			repoName:     "myorg/app",
			actions:      []string{"pull", "push"},
			want:         "repository:myorg/app:pull,push",
		},
		{
			name:         "single action",
			resourceType: "repository",
			repoName:     "myorg/app",
			actions:      []string{"pull"},
			want:         "repository:myorg/app:pull",
		},
		{
			name:         "no actions",
			resourceType: "repository",
			repoName:     "myorg/app",
			actions:      []string{},
			want:         "repository:myorg/app:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatScope(tt.resourceType, tt.repoName, tt.actions); got != tt.want {
				t.Errorf("FormatScope() = %v, want %v", got, tt.want)
			}
		})
	}
}
