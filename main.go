package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

func main() {
	// Load environment variables
	baseURL := os.Getenv("VBR_SERVER_URL")
	if baseURL == "" {
		serverAddress := promptUser("Enter VBR Server IP or DNS name: ")
		baseURL = fmt.Sprintf("https://%s:9419", serverAddress)
	}
	username := getEnv("VBR_USERNAME", "Enter VBR Username: ")
	password := getEnv("VBR_PASSWORD", "Enter VBR Password: ")

	// Authenticate and get token
	token, err := authenticate(baseURL, username, password)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Get and print server info
	serverInfo, err := getServerInfo(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to get server info: %v", err)
	}
	printServerInfo(serverInfo)

	// Get and print credentials
	credentials, err := getCredentials(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to get credentials: %v", err)
	}
	printCredentials(credentials)

	// Get and print cloud credentials
	cloudCredentials, err := getCloudCredentials(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to get cloud credentials: %v", err)
	}
	printCloudCredentials(cloudCredentials)

	// Get and print KMS servers
	kmsServers, err := getKMSServers(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to get KMS servers: %v", err)
	}
	printKMSServers(kmsServers)

	// Get and print managed servers
	managedServers, err := getManagedServers(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to get managed servers: %v", err)
	}
	printManagedServers(managedServers)

	// Get and print repositories
	repositories, err := getRepositories(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to get repositories: %v", err)
	}
	printRepositories(repositories)

	// Get and print scale-out repositories
	scaleOutRepositories, err := getScaleOutRepositories(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to get scale-out repositories: %v", err)
	}
	printScaleOutRepositories(scaleOutRepositories)

	// Get and print proxies
	proxies, err := getProxies(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to get proxies: %v", err)
	}
	printProxies(proxies)

	// Get and print list of backup jobs
	jobs, err := listBackupJobs(baseURL, token)
	if err != nil {
		log.Fatalf("Failed to list backup jobs: %v", err)
	}
	printBackupJobs(jobs)
}

// promptUser prompts the user for input and returns the entered value
func promptUser(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}

// getEnv retrieves the environment variable or prompts the user to input it if not set
func getEnv(key, prompt string) string {
	value := os.Getenv(key)
	if value == "" {
		value = promptUser(prompt)
	}
	return value
}

// Helper function to format nil values gracefully
func formatNilValue(val interface{}) string {
	if val == nil {
		return "N/A"
	}
	return fmt.Sprintf("%v", val)
}

// authenticate logs in to the Veeam API and retrieves the authentication token
func authenticate(baseURL, username, password string) (string, error) {
	authURL := fmt.Sprintf("%s/api/oauth2/token", baseURL)

	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)
	data.Set("refresh_token", "")
	data.Set("code", "")
	data.Set("use_short_term_refresh", "")
	data.Set("vbr_token", "")

	// Create HTTP client with insecure TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip certificate verification
		},
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", authURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-api-version", "1.1-rev2")
	req.Header.Set("accept", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to authenticate: %s", string(body))
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Extract token
	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access token not found in response")
	}

	return token, nil
}

// getServerInfo retrieves the server info from the Veeam API
func getServerInfo(baseURL, token string) (map[string]interface{}, error) {
	return getAPIData(fmt.Sprintf("%s/api/v1/serverInfo", baseURL), token)
}

// getCredentials retrieves the credentials from the Veeam API
func getCredentials(baseURL, token string) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/credentials", baseURL), token)
}

// getCloudCredentials retrieves the cloud credentials from the Veeam API
func getCloudCredentials(baseURL, token string) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/cloudCredentials", baseURL), token)
}

// getKMSServers retrieves the KMS servers from the Veeam API
func getKMSServers(baseURL, token string) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/kmsServers", baseURL), token)
}

// getManagedServers retrieves the managed servers from the Veeam API
func getManagedServers(baseURL, token string) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/backupInfrastructure/managedServers", baseURL), token)
}

// getRepositories retrieves the repositories from the Veeam API
func getRepositories(baseURL, token string) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/backupInfrastructure/repositories", baseURL), token)
}

// getScaleOutRepositories retrieves the scale-out repositories from the Veeam API
func getScaleOutRepositories(baseURL, token string) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/backupInfrastructure/scaleOutRepositories", baseURL), token)
}

// getProxies retrieves the proxies from the Veeam API
func getProxies(baseURL, token string) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/backupInfrastructure/proxies", baseURL), token)
}

// listBackupJobs retrieves the list of backup jobs from the Veeam API
func listBackupJobs(baseURL, token string) ([]map[string]interface{}, error) {
	jobsURL := fmt.Sprintf("%s/api/v1/jobs", baseURL) // Updated endpoint

	// Create HTTP client with insecure TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip certificate verification
		},
	}

	// Create HTTP request
	req, err := http.NewRequest("GET", jobsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-api-version", "1.1-rev2") // Set correct API version header

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get jobs: %s", string(body))
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Extract job list
	jobs, ok := result["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("job data not found in response")
	}

	// Convert jobs to a list of maps
	jobList := make([]map[string]interface{}, 0)
	for _, job := range jobs {
		if jobMap, ok := job.(map[string]interface{}); ok {
			jobList = append(jobList, jobMap)
		}
	}

	return jobList, nil
}

// getAPIData retrieves a single item from the Veeam API
func getAPIData(url, token string) (map[string]interface{}, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip certificate verification
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-api-version", "1.1-rev2")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get data: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// getAPIList retrieves a list of items from the Veeam API
func getAPIList(url, token string) ([]interface{}, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip certificate verification
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-api-version", "1.1-rev2")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get data: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	data, ok := result["data"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("data not found in response")
	}

	return data, nil
}

// printServerInfo prints the server info in a readable format
func printServerInfo(info map[string]interface{}) {
	fmt.Println("Server Info:")
	fmt.Printf("  Name: %s\n", info["name"])
	fmt.Printf("  Build Version: %s\n", info["buildVersion"])
	fmt.Printf("  Database Vendor: %s\n", info["databaseVendor"])
	fmt.Printf("  SQL Server Version: %s\n", info["sqlServerVersion"])
	fmt.Printf("  VBR ID: %s\n", info["vbrId"])
	fmt.Println()
}

// printCredentials prints the credentials in a readable format
func printCredentials(credentials []interface{}) {
	fmt.Println("Credentials:")
	for _, cred := range credentials {
		credMap := cred.(map[string]interface{})
		fmt.Printf("  Description: %s\n", credMap["description"])
		fmt.Printf("  Username: %s\n", credMap["username"])
		fmt.Printf("  Type: %s\n", credMap["type"])
		fmt.Println()
	}
}

// printCloudCredentials prints the cloud credentials in a readable format
func printCloudCredentials(credentials []interface{}) {
	fmt.Println("Cloud Credentials:")
	for _, cred := range credentials {
		credMap := cred.(map[string]interface{})
		fmt.Printf("  Description: %s\n", credMap["description"])
		fmt.Printf("  Type: %s\n", credMap["type"])
		fmt.Println()
	}
}

// printKMSServers prints the KMS servers in a readable format
func printKMSServers(servers []interface{}) {
	fmt.Println("KMS Servers:")
	for _, server := range servers {
		serverMap := server.(map[string]interface{})
		fmt.Printf("  ID: %s\n", serverMap["id"])
		fmt.Printf("  Name: %s\n", serverMap["name"])
		fmt.Println()
	}
}

// printManagedServers prints the managed servers in a readable format
func printManagedServers(servers []interface{}) {
	fmt.Println("Managed Servers:")
	for _, server := range servers {
		serverMap := server.(map[string]interface{})
		fmt.Printf("  Name: %s\n", serverMap["name"])
		fmt.Printf("  Type: %s\n", serverMap["type"])
		fmt.Printf("  Status: %s\n", serverMap["status"])
		fmt.Println()
	}
}

// printRepositories prints the repositories in a readable format
func printRepositories(repositories []interface{}) {
	fmt.Println("Repositories:")
	for _, repo := range repositories {
		repoMap := repo.(map[string]interface{})
		fmt.Printf("  Name: %s\n", repoMap["name"])
		fmt.Printf("  Type: %s\n", repoMap["type"])
		fmt.Printf("  Description: %s\n", repoMap["description"])
		fmt.Println()
	}
}

// printScaleOutRepositories prints the scale-out repositories in a readable format
func printScaleOutRepositories(repositories []interface{}) {
	fmt.Println("Scale-Out Repositories:")
	for _, repo := range repositories {
		repoMap := repo.(map[string]interface{})
		fmt.Printf("  Name: %s\n", repoMap["name"])
		fmt.Printf("  Description: %s\n", repoMap["description"])
		fmt.Println()
	}
}

// printProxies prints the proxies in a readable format
func printProxies(proxies []interface{}) {
	fmt.Println("Proxies:")
	for _, proxy := range proxies {
		proxyMap := proxy.(map[string]interface{})
		fmt.Printf("  Name: %s\n", proxyMap["name"])
		fmt.Printf("  Type: %s\n", proxyMap["type"])
		fmt.Printf("  Description: %s\n", proxyMap["description"])
		fmt.Println()
	}
}

// printBackupJobs prints the backup jobs in a readable format
func printBackupJobs(jobs []map[string]interface{}) {
	fmt.Println("Backup Jobs:")
	for _, job := range jobs {
		fmt.Printf("Job Name: %s\n", job["name"])
		fmt.Printf("ID: %s\n", job["id"])
		fmt.Printf("Description: %s\n", formatNilValue(job["description"]))
		fmt.Printf("Type: %s\n", formatNilValue(job["type"]))
		fmt.Printf("Is Disabled: %v\n", job["isDisabled"])
		fmt.Printf("Is High Priority: %v\n", job["isHighPriority"])

		// Print virtual machines included in the job
		if vms, ok := job["virtualMachines"].(map[string]interface{}); ok {
			if includes, ok := vms["includes"].([]interface{}); ok {
				fmt.Println("Included VMs:")
				for _, vm := range includes {
					if vmMap, ok := vm.(map[string]interface{}); ok {
						fmt.Printf("  - Name: %s, Host: %s, Size: %s\n", vmMap["name"], vmMap["hostName"], vmMap["size"])
					}
				}
			}
		}

		// Print storage information
		if storage, ok := job["storage"].(map[string]interface{}); ok {
			fmt.Printf("Backup Repository ID: %s\n", storage["backupRepositoryId"])
			if retentionPolicy, ok := storage["retentionPolicy"].(map[string]interface{}); ok {
				fmt.Printf("Retention Policy: %s for %v days\n", retentionPolicy["type"], retentionPolicy["quantity"])
			}
		}

		// Print schedule information
		if schedule, ok := job["schedule"].(map[string]interface{}); ok {
			fmt.Printf("Run Automatically: %v\n", schedule["runAutomatically"])
			if daily, ok := schedule["daily"].(map[string]interface{}); ok {
				fmt.Printf("Daily Schedule: %s at %s\n", daily["dailyKind"], daily["localTime"])
			}
		}

		// Additional blank line for clarity
		fmt.Println()
	}
}
