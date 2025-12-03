package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	// BcryptCost is the cost parameter used for bcrypt password hashing.
	BcryptCost = 10
	// DefaultPasswordLength is the length of generated random passwords in bytes.
	DefaultPasswordLength = 32
)

// GeneratePassword generates a random password string.
func GeneratePassword() (string, error) {
	bytes := make([]byte, DefaultPasswordLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// AddUser adds a user with the given username and hashed password to the config file.
func AddUser(configPath, username, hashedPassword string) error {
	// Get original file permissions
	fileInfo, err := os.Stat(configPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}
	originalMode := fileInfo.Mode()

	// Read the existing config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse as generic YAML to preserve formatting
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Find or create the users section
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return fmt.Errorf("invalid config file structure")
	}

	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return fmt.Errorf("config file root is not a mapping")
	}

	var usersNode *yaml.Node
	for i := 0; i < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "users" {
			usersNode = doc.Content[i+1]
			break
		}
	}

	if usersNode == nil {
		// Create users section if it doesn't exist
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "users"}
		usersNode = &yaml.Node{Kind: yaml.MappingNode}
		doc.Content = append(doc.Content, keyNode, usersNode)
	}

	if usersNode.Kind != yaml.MappingNode {
		return fmt.Errorf("users section is not a mapping")
	}

	// Check if user already exists
	for i := 0; i < len(usersNode.Content); i += 2 {
		if usersNode.Content[i].Value == username {
			return fmt.Errorf("user %q already exists", username)
		}
	}

	// Add the new user
	usernameNode := &yaml.Node{Kind: yaml.ScalarNode, Value: username}
	passwordMapNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "password"},
			{Kind: yaml.ScalarNode, Value: hashedPassword, Style: yaml.DoubleQuotedStyle},
		},
	}
	usersNode.Content = append(usersNode.Content, usernameNode, passwordMapNode)

	// Write back to the file
	output, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, output, originalMode.Perm()); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
