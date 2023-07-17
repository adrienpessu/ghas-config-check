package main

import (
	"bufio"
	"bytes"
	json "encoding/json"
	"fmt"
	"io"
	log "log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {

	token := os.Getenv("GITHUB_TOKEN")
	repository := os.Getenv("GITHUB_REPOSITORY")
	workspace := os.Getenv("GITHUB_WORKSPACE")
	url := "https://api.github.com"
	if os.Getenv("GITHUB_API_URL") != "" {
		url = os.Getenv("GITHUB_API_URL")
	}

	codeScanningEnabled := readWorkflowFiles(workspace + "/.github/workflows")
	if codeScanningEnabled {

	}
	secretScanningAlerts, secretScanningEnabled := getSecretScanningAlerts(token, url, repository, 1, 0)
	dependabotScanningAlerts, dependabotScanningEnabled := getDependabotAlerts(token, url, repository, 1, 0)

	issueContent := ""
	if codeScanningEnabled {
		codeScanningAlerts, _ := getCodeScanningAlerts(token, url, repository, 1, 0)
		issueContent += fmt.Sprintln("Code Scanning Alerts: ", codeScanningAlerts)
	} else {
		issueContent += fmt.Sprintln("Code Scanning is not enabled")
	}

	if secretScanningEnabled {
		issueContent += fmt.Sprintln("Secret Scanning Alerts: ", secretScanningAlerts)
	} else {
		issueContent += fmt.Sprintln("Secret Scanning is not enabled")
	}

	if dependabotScanningEnabled {
		issueContent += fmt.Sprintln("Dependabot Alerts: ", dependabotScanningAlerts)
	} else {
		issueContent += fmt.Sprintln("Dependabot is not enabled")
	}

	if !codeScanningEnabled || !secretScanningEnabled || !dependabotScanningEnabled {
		createIssue(token, url, repository, "Security Scan Results", issueContent)
		os.Exit(1)
	}

}

func createIssue(token string, instance string, repo string, title string, content string) Issue {

	url := fmt.Sprintf("%v/repos/%v/issues", instance, repo)
	method := "POST"

	client := &http.Client{}

	issueToAdd := make(map[string]string)
	issueToAdd["title"] = title
	issueToAdd["body"] = content

	fmt.Println(issueToAdd)

	requestBody, err := json.Marshal(issueToAdd)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(requestBody))

	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Accept", "application/vnd.github+json")
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	fmt.Println(res.StatusCode)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	var response Issue
	json.Unmarshal(body, &response)

	return response

}

func getSecretScanningAlerts(token string, instance string, repo string, page int, counter int) (int, bool) {

	perPage := 100

	url := fmt.Sprintf("%v/repos/%v/secret-scanning/alerts?per_page=%d&state=open&page=%d", instance, repo, perPage, page)
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return 0, false
	}
	req.Header.Add("Accept", "application/vnd.github+json")
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)

	if res.StatusCode == 404 {
		return 0, false
	}

	if err != nil {
		fmt.Println(err)
		return 0, false
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return 0, false
	}

	var response Alert
	json.Unmarshal([]byte(string(body)), &response)

	if len(response) > 0 && len(response) == perPage {
		nextPage := page + 1
		counter += len(response)
		nextPageCount, _ := getSecretScanningAlerts(token, instance, repo, nextPage, counter)
		return len(response) + nextPageCount, true
	} else if len(response) == 0 {
		return 0, true
	}

	return len(response), true
}

func readWorkflowFiles(workflowDirectory string) bool {
	codeScanningActionExists := false
	files, _ := os.ReadDir(workflowDirectory)

	for _, f := range files {
		if !f.IsDir() {
			file, _ := os.Open(fmt.Sprintf("%v/%v", workflowDirectory, f.Name()))
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if strings.Contains(scanner.Text(), "codeql-action") {
					codeScanningActionExists = true
				}
			}
		}
	}

	return codeScanningActionExists
}

func getCodeScanningAlerts(token string, instance string, repo string, page int, counter int) (int, bool) {

	perPage := 100

	url := fmt.Sprintf("%v/repos/%v/code-scanning/alerts?per_page=%d&state=open&page=%d", instance, repo, perPage, page)
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return 0, false
	}
	req.Header.Add("Accept", "application/vnd.github+json")
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)

	if res.StatusCode == 404 {
		return 0, false
	}

	if err != nil {
		fmt.Println(err)
		return 0, false
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return 0, false
	}

	var response Alert
	json.Unmarshal([]byte(string(body)), &response)

	if len(response) > 0 && len(response) == perPage {
		nextPage := page + 1
		counter += len(response)
		nextPageCount, _ := getCodeScanningAlerts(token, instance, repo, nextPage, counter)
		return len(response) + nextPageCount, true
	} else if len(response) == 0 {
		return 0, true
	}

	return len(response), true
}

func getDependabotAlerts(token string, instance string, repo string, page int, counter int) (int, bool) {

	perPage := 100

	url := fmt.Sprintf("%v/repos/%v/dependabot/alerts?per_page=%d&state=open&page=%d", instance, repo, perPage, page)
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return 0, false
	}
	req.Header.Add("Accept", "application/vnd.github+json")
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)

	if res.StatusCode == 404 || res.StatusCode == 403 {
		return 0, false
	}

	if err != nil {
		fmt.Println(err)
		return 0, false
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return 0, false
	}

	var response Alert
	json.Unmarshal([]byte(string(body)), &response)

	if len(response) > 0 && len(response) == perPage {
		nextPage := page + 1
		counter += len(response)
		nextPageCount, _ := getDependabotAlerts(token, instance, repo, nextPage, counter)
		return len(response) + nextPageCount, true
	} else if len(response) == 0 {
		return 0, true
	}

	return len(response), true
}

type Alert []struct {
	Number      int       `json:"number"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	URL         string    `json:"url"`
	HTMLURL     string    `json:"html_url"`
	State       string    `json:"state"`
	FixedAt     any       `json:"fixed_at"`
	DismissedBy struct {
		Login             string `json:"login"`
		ID                int    `json:"id"`
		NodeID            string `json:"node_id"`
		AvatarURL         string `json:"avatar_url"`
		GravatarID        string `json:"gravatar_id"`
		URL               string `json:"url"`
		HTMLURL           string `json:"html_url"`
		FollowersURL      string `json:"followers_url"`
		FollowingURL      string `json:"following_url"`
		GistsURL          string `json:"gists_url"`
		StarredURL        string `json:"starred_url"`
		SubscriptionsURL  string `json:"subscriptions_url"`
		OrganizationsURL  string `json:"organizations_url"`
		ReposURL          string `json:"repos_url"`
		EventsURL         string `json:"events_url"`
		ReceivedEventsURL string `json:"received_events_url"`
		Type              string `json:"type"`
		SiteAdmin         bool   `json:"site_admin"`
	} `json:"dismissed_by"`
	DismissedAt      time.Time `json:"dismissed_at"`
	DismissedReason  string    `json:"dismissed_reason"`
	DismissedComment string    `json:"dismissed_comment"`
	Rule             struct {
		ID                    string   `json:"id"`
		Severity              string   `json:"severity"`
		Description           string   `json:"description"`
		Name                  string   `json:"name"`
		Tags                  []string `json:"tags"`
		SecuritySeverityLevel string   `json:"security_severity_level"`
	} `json:"rule"`
	Tool struct {
		Name    string `json:"name"`
		GUID    any    `json:"guid"`
		Version string `json:"version"`
	} `json:"tool"`
	MostRecentInstance struct {
		Ref         string `json:"ref"`
		AnalysisKey string `json:"analysis_key"`
		Environment string `json:"environment"`
		Category    string `json:"category"`
		State       string `json:"state"`
		CommitSha   string `json:"commit_sha"`
		Message     struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path        string `json:"path"`
			StartLine   int    `json:"start_line"`
			EndLine     int    `json:"end_line"`
			StartColumn int    `json:"start_column"`
			EndColumn   int    `json:"end_column"`
		} `json:"location"`
		Classifications []string `json:"classifications"`
	} `json:"most_recent_instance"`
	InstancesURL string `json:"instances_url"`
}

type Issue struct {
	ID            int    `json:"id"`
	NodeID        string `json:"node_id"`
	URL           string `json:"url"`
	RepositoryURL string `json:"repository_url"`
	LabelsURL     string `json:"labels_url"`
	CommentsURL   string `json:"comments_url"`
	EventsURL     string `json:"events_url"`
	HTMLURL       string `json:"html_url"`
	Number        int    `json:"number"`
	State         string `json:"state"`
	Title         string `json:"title"`
	Body          string `json:"body"`
	User          struct {
		Login             string `json:"login"`
		ID                int    `json:"id"`
		NodeID            string `json:"node_id"`
		AvatarURL         string `json:"avatar_url"`
		GravatarID        string `json:"gravatar_id"`
		URL               string `json:"url"`
		HTMLURL           string `json:"html_url"`
		FollowersURL      string `json:"followers_url"`
		FollowingURL      string `json:"following_url"`
		GistsURL          string `json:"gists_url"`
		StarredURL        string `json:"starred_url"`
		SubscriptionsURL  string `json:"subscriptions_url"`
		OrganizationsURL  string `json:"organizations_url"`
		ReposURL          string `json:"repos_url"`
		EventsURL         string `json:"events_url"`
		ReceivedEventsURL string `json:"received_events_url"`
		Type              string `json:"type"`
		SiteAdmin         bool   `json:"site_admin"`
	} `json:"user"`
	Labels []struct {
		ID          int    `json:"id"`
		NodeID      string `json:"node_id"`
		URL         string `json:"url"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Color       string `json:"color"`
		Default     bool   `json:"default"`
	} `json:"labels"`
	Assignee struct {
		Login             string `json:"login"`
		ID                int    `json:"id"`
		NodeID            string `json:"node_id"`
		AvatarURL         string `json:"avatar_url"`
		GravatarID        string `json:"gravatar_id"`
		URL               string `json:"url"`
		HTMLURL           string `json:"html_url"`
		FollowersURL      string `json:"followers_url"`
		FollowingURL      string `json:"following_url"`
		GistsURL          string `json:"gists_url"`
		StarredURL        string `json:"starred_url"`
		SubscriptionsURL  string `json:"subscriptions_url"`
		OrganizationsURL  string `json:"organizations_url"`
		ReposURL          string `json:"repos_url"`
		EventsURL         string `json:"events_url"`
		ReceivedEventsURL string `json:"received_events_url"`
		Type              string `json:"type"`
		SiteAdmin         bool   `json:"site_admin"`
	} `json:"assignee"`
	Assignees []struct {
		Login             string `json:"login"`
		ID                int    `json:"id"`
		NodeID            string `json:"node_id"`
		AvatarURL         string `json:"avatar_url"`
		GravatarID        string `json:"gravatar_id"`
		URL               string `json:"url"`
		HTMLURL           string `json:"html_url"`
		FollowersURL      string `json:"followers_url"`
		FollowingURL      string `json:"following_url"`
		GistsURL          string `json:"gists_url"`
		StarredURL        string `json:"starred_url"`
		SubscriptionsURL  string `json:"subscriptions_url"`
		OrganizationsURL  string `json:"organizations_url"`
		ReposURL          string `json:"repos_url"`
		EventsURL         string `json:"events_url"`
		ReceivedEventsURL string `json:"received_events_url"`
		Type              string `json:"type"`
		SiteAdmin         bool   `json:"site_admin"`
	} `json:"assignees"`
	Milestone struct {
		URL         string `json:"url"`
		HTMLURL     string `json:"html_url"`
		LabelsURL   string `json:"labels_url"`
		ID          int    `json:"id"`
		NodeID      string `json:"node_id"`
		Number      int    `json:"number"`
		State       string `json:"state"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Creator     struct {
			Login             string `json:"login"`
			ID                int    `json:"id"`
			NodeID            string `json:"node_id"`
			AvatarURL         string `json:"avatar_url"`
			GravatarID        string `json:"gravatar_id"`
			URL               string `json:"url"`
			HTMLURL           string `json:"html_url"`
			FollowersURL      string `json:"followers_url"`
			FollowingURL      string `json:"following_url"`
			GistsURL          string `json:"gists_url"`
			StarredURL        string `json:"starred_url"`
			SubscriptionsURL  string `json:"subscriptions_url"`
			OrganizationsURL  string `json:"organizations_url"`
			ReposURL          string `json:"repos_url"`
			EventsURL         string `json:"events_url"`
			ReceivedEventsURL string `json:"received_events_url"`
			Type              string `json:"type"`
			SiteAdmin         bool   `json:"site_admin"`
		} `json:"creator"`
		OpenIssues   int       `json:"open_issues"`
		ClosedIssues int       `json:"closed_issues"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		ClosedAt     time.Time `json:"closed_at"`
		DueOn        time.Time `json:"due_on"`
	} `json:"milestone"`
	Locked           bool   `json:"locked"`
	ActiveLockReason string `json:"active_lock_reason"`
	Comments         int    `json:"comments"`
	PullRequest      struct {
		URL      string `json:"url"`
		HTMLURL  string `json:"html_url"`
		DiffURL  string `json:"diff_url"`
		PatchURL string `json:"patch_url"`
	} `json:"pull_request"`
	ClosedAt  any       `json:"closed_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ClosedBy  struct {
		Login             string `json:"login"`
		ID                int    `json:"id"`
		NodeID            string `json:"node_id"`
		AvatarURL         string `json:"avatar_url"`
		GravatarID        string `json:"gravatar_id"`
		URL               string `json:"url"`
		HTMLURL           string `json:"html_url"`
		FollowersURL      string `json:"followers_url"`
		FollowingURL      string `json:"following_url"`
		GistsURL          string `json:"gists_url"`
		StarredURL        string `json:"starred_url"`
		SubscriptionsURL  string `json:"subscriptions_url"`
		OrganizationsURL  string `json:"organizations_url"`
		ReposURL          string `json:"repos_url"`
		EventsURL         string `json:"events_url"`
		ReceivedEventsURL string `json:"received_events_url"`
		Type              string `json:"type"`
		SiteAdmin         bool   `json:"site_admin"`
	} `json:"closed_by"`
	AuthorAssociation string `json:"author_association"`
	StateReason       string `json:"state_reason"`
}
