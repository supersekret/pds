package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type Config struct {
	Hostname      string
	AdminPassword string
	Protocol      string
}

type Account struct {
	Handle string `json:"handle"`
	Email  string `json:"email"`
	DID    string `json:"did"`
}

type RepoListResponse struct {
	Repos []struct {
		DID string `json:"did"`
	} `json:"repos"`
}

type InviteCodeResponse struct {
	Code string `json:"code"`
}

type CreateAccountRequest struct {
	Email      string `json:"email"`
	Handle     string `json:"handle"`
	Password   string `json:"password"`
	InviteCode string `json:"inviteCode"`
}

type CreateAccountResponse struct {
	DID string `json:"did"`
}

func getConfig() *Config {
	// Use flag values if provided, otherwise fall back to env vars
	hostnameVal := hostname
	if hostnameVal == "" {
		hostnameVal = getEnvOrDefault("PDS_HOSTNAME", "localhost:3000")
	}
	
	passwordVal := adminPassword
	if passwordVal == "" {
		passwordVal = getEnvOrDefault("PDS_ADMIN_PASSWORD", "admin")
	}
	
	protocolVal := protocol
	if protocolVal == "" {
		protocolVal = getEnvOrDefault("PDS_PROTOCOL", "http")
	}
	
	return &Config{
		Hostname:      hostnameVal,
		AdminPassword: passwordVal,
		Protocol:      protocolVal,
	}
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&hostname, "hostname", "H", "", "PDS hostname (overrides PDS_HOSTNAME env var)")
	rootCmd.PersistentFlags().StringVarP(&adminPassword, "password", "p", "", "Admin password (overrides PDS_ADMIN_PASSWORD env var)")
	rootCmd.PersistentFlags().StringVar(&protocol, "protocol", "", "Protocol (http/https, overrides PDS_PROTOCOL env var)")

	// Add subcommands
	rootCmd.AddCommand(accountCmd)
	rootCmd.AddCommand(createInviteCmd)
	rootCmd.AddCommand(requestCrawlCmd)

	// Add account subcommands
	accountCmd.AddCommand(accountListCmd)
	accountCmd.AddCommand(accountCreateCmd)
	accountCmd.AddCommand(accountDeleteCmd)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func makeRequest(config *Config, method, path string, body io.Reader, useAuth bool) (*http.Response, error) {
	url := fmt.Sprintf("%s://%s%s", config.Protocol, config.Hostname, path)
	
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	
	if useAuth {
		req.SetBasicAuth("admin", config.AdminPassword)
	}
	
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func generatePassword() string {
	bytes := make([]byte, 24)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:24]
}

func listAccounts(config *Config) error {
	// Get list of DIDs
	resp, err := makeRequest(config, "GET", "/xrpc/com.atproto.sync.listRepos?limit=100", nil, false)
	if err != nil {
		return fmt.Errorf("failed to get repo list: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to get repo list: status %d", resp.StatusCode)
	}
	
	var repoList RepoListResponse
	if err := json.NewDecoder(resp.Body).Decode(&repoList); err != nil {
		return fmt.Errorf("failed to decode repo list: %v", err)
	}
	
	fmt.Printf("%-30s %-30s %s\n", "Handle", "Email", "DID")
	
	if len(repoList.Repos) == 0 {
		return nil
	}
	
	// Get account info for each DID
	for _, repo := range repoList.Repos {
		path := fmt.Sprintf("/xrpc/com.atproto.admin.getAccountInfo?did=%s", repo.DID)
		resp, err := makeRequest(config, "GET", path, nil, true)
		if err != nil {
			continue
		}
		
		if resp.StatusCode == 200 {
			var account Account
			if err := json.NewDecoder(resp.Body).Decode(&account); err == nil {
				fmt.Printf("%-30s %-30s %s\n", account.Handle, account.Email, account.DID)
			}
		}
		resp.Body.Close()
	}
	
	return nil
}

func createAccount(config *Config, email, handle string) error {
	if email == "" || handle == "" {
		return fmt.Errorf("email and handle are required")
	}
	
	// Generate password
	password := generatePassword()
	
	// Create invite code
	inviteReq := map[string]int{"useCount": 1}
	reqBody, _ := json.Marshal(inviteReq)
	
	resp, err := makeRequest(config, "POST", "/xrpc/com.atproto.server.createInviteCode", bytes.NewBuffer(reqBody), true)
	if err != nil {
		return fmt.Errorf("failed to create invite code: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to create invite code: status %d", resp.StatusCode)
	}
	
	var inviteResp InviteCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&inviteResp); err != nil {
		return fmt.Errorf("failed to decode invite response: %v", err)
	}
	
	// Create account
	createReq := CreateAccountRequest{
		Email:      email,
		Handle:     handle,
		Password:   password,
		InviteCode: inviteResp.Code,
	}
	
	reqBody, _ = json.Marshal(createReq)
	resp, err = makeRequest(config, "POST", "/xrpc/com.atproto.server.createAccount", bytes.NewBuffer(reqBody), false)
	if err != nil {
		return fmt.Errorf("failed to create account: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create account: status %d, body: %s", resp.StatusCode, string(body))
	}
	
	var createResp CreateAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		return fmt.Errorf("failed to decode create response: %v", err)
	}
	
	fmt.Println()
	fmt.Println("Account created successfully!")
	fmt.Println("-----------------------------")
	fmt.Printf("Handle   : %s\n", handle)
	fmt.Printf("DID      : %s\n", createResp.DID)
	fmt.Printf("Password : %s\n", password)
	fmt.Println("-----------------------------")
	fmt.Println("Save this password, it will not be displayed again.")
	fmt.Println()
	
	return nil
}

func createInviteCode(config *Config) error {
	reqBody := []byte(`{"useCount": 1}`)
	
	resp, err := makeRequest(config, "POST", "/xrpc/com.atproto.server.createInviteCode", bytes.NewBuffer(reqBody), true)
	if err != nil {
		return fmt.Errorf("failed to create invite code: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to create invite code: status %d", resp.StatusCode)
	}
	
	var inviteResp InviteCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&inviteResp); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	
	fmt.Println(inviteResp.Code)
	return nil
}

func deleteAccount(config *Config, did string) error {
	if did == "" {
		return fmt.Errorf("DID is required")
	}
	
	if !strings.HasPrefix(did, "did:") {
		return fmt.Errorf("DID must start with 'did:'")
	}
	
	reqBody := fmt.Sprintf(`{"did": "%s"}`, did)
	
	resp, err := makeRequest(config, "POST", "/xrpc/com.atproto.admin.deleteAccount", strings.NewReader(reqBody), true)
	if err != nil {
		return fmt.Errorf("failed to delete account: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to delete account: status %d", resp.StatusCode)
	}
	
	fmt.Printf("%s deleted\n", did)
	return nil
}

func requestCrawl(config *Config, relayHost string) error {
	if relayHost == "" {
		relayHost = "bsky.network"
	}
	
	reqBody := fmt.Sprintf(`{"hostname": "%s"}`, config.Hostname)
	
	resp, err := makeRequest(config, "POST", fmt.Sprintf("/xrpc/com.atproto.sync.requestCrawl?hostname=%s", relayHost), strings.NewReader(reqBody), false)
	if err != nil {
		return fmt.Errorf("failed to request crawl: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to request crawl: status %d", resp.StatusCode)
	}
	
	fmt.Printf("Crawl requested from %s\n", relayHost)
	return nil
}

var (
	hostname      string
	adminPassword string
	protocol      string
)

var rootCmd = &cobra.Command{
	Use:   "pdsadmin",
	Short: "AT Protocol PDS administration tool",
	Long:  `A command-line tool for administering AT Protocol Personal Data Server (PDS) instances.`,
}

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage user accounts",
	Long:  `Create, list, and delete user accounts on the PDS instance.`,
}

var accountListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all accounts",
	Long:  `List all user accounts on the PDS instance.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config := getConfig()
		return listAccounts(config)
	},
}

var accountCreateCmd = &cobra.Command{
	Use:   "create <email> <handle>",
	Short: "Create a new account",
	Long:  `Create a new user account with the specified email and handle.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := getConfig()
		return createAccount(config, args[0], args[1])
	},
}

var accountDeleteCmd = &cobra.Command{
	Use:   "delete <did>",
	Short: "Delete an account",
	Long:  `Delete the account specified by DID.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := getConfig()
		return deleteAccount(config, args[0])
	},
}

var createInviteCmd = &cobra.Command{
	Use:   "create-invite-code",
	Short: "Create an invite code",
	Long:  `Create a new invite code that can be used to register accounts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config := getConfig()
		return createInviteCode(config)
	},
}

var requestCrawlCmd = &cobra.Command{
	Use:   "request-crawl [relay-host]",
	Short: "Request crawl from relay",
	Long:  `Request a crawl from the specified relay host (defaults to bsky.network).`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := getConfig()
		relayHost := "bsky.network"
		if len(args) > 0 {
			relayHost = args[0]
		}
		return requestCrawl(config, relayHost)
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}