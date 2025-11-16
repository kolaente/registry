package acl

import (
	"path/filepath"
	"strings"

	"github.com/kolaente/registry/pkg/config"
)

// Matcher handles ACL matching logic
type Matcher struct {
	rules []config.ACLRule
}

// NewMatcher creates a new ACL matcher
func NewMatcher(rules []config.ACLRule) *Matcher {
	return &Matcher{
		rules: rules,
	}
}

// GetAllowedActions returns the allowed actions for a user on a repository
func (m *Matcher) GetAllowedActions(account, repository string) []string {
	allowedActions := make(map[string]bool)

	for _, rule := range m.rules {
		// Check if the account matches
		if rule.Account != account && rule.Account != "*" {
			continue
		}

		// Check if the repository name matches the pattern
		if !m.matchPattern(rule.Name, repository) {
			continue
		}

		// Add allowed actions
		for _, action := range rule.Actions {
			if action == "*" {
				// Wildcard grants all actions
				allowedActions["pull"] = true
				allowedActions["push"] = true
				allowedActions["delete"] = true
			} else {
				allowedActions[action] = true
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(allowedActions))
	for action := range allowedActions {
		result = append(result, action)
	}

	return result
}

// HasAccess checks if a user has access to perform specific actions on a repository
func (m *Matcher) HasAccess(account, repository string, requiredActions []string) bool {
	allowedActions := m.GetAllowedActions(account, repository)
	allowedMap := make(map[string]bool)
	for _, action := range allowedActions {
		allowedMap[action] = true
	}

	for _, required := range requiredActions {
		if !allowedMap[required] {
			return false
		}
	}

	return true
}

// matchPattern matches a repository name against a pattern
// Supports wildcards: * (matches any characters) and ? (matches single character)
func (m *Matcher) matchPattern(pattern, name string) bool {
	// Handle exact wildcard match
	if pattern == "*" {
		return true
	}

	// Use filepath.Match for glob pattern matching
	// This supports * and ? wildcards
	matched, err := filepath.Match(pattern, name)
	if err != nil {
		// If pattern is invalid, treat as no match
		return false
	}

	return matched
}

// ParseScope parses a Docker registry scope string
// Format: "repository:name:action1,action2"
func ParseScope(scope string) (resourceType, name string, actions []string) {
	parts := strings.Split(scope, ":")
	if len(parts) < 3 {
		return "", "", nil
	}

	resourceType = parts[0]
	name = parts[1]
	actions = strings.Split(parts[2], ",")

	return
}

// FormatScope formats a scope string for JWT claims
func FormatScope(resourceType, name string, actions []string) string {
	return resourceType + ":" + name + ":" + strings.Join(actions, ",")
}
