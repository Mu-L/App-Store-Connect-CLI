package asc

import (
	"strconv"
	"strings"
)

// AgeRatingAuditRow reports one app's social-media capability responses.
type AgeRatingAuditRow struct {
	AppID                    string   `json:"appId"`
	Name                     string   `json:"name,omitempty"`
	BundleID                 string   `json:"bundleId,omitempty"`
	SocialMedia              string   `json:"socialMedia"`
	SocialMediaAgeRestricted string   `json:"socialMediaAgeRestricted"`
	MessagingAndChat         string   `json:"messagingAndChat"`
	AgeAssurance             string   `json:"ageAssurance"`
	MissingResponses         []string `json:"missingResponses"`
	Ready                    bool     `json:"ready"`
	Error                    string   `json:"error,omitempty"`
}

// AgeRatingAuditResult summarizes social-media capability readiness per app.
type AgeRatingAuditResult struct {
	Apps         []AgeRatingAuditRow `json:"apps"`
	ReadyCount   int                 `json:"readyCount"`
	MissingCount int                 `json:"missingCount"`
	ErrorCount   int                 `json:"errorCount"`
}

func ageRatingAuditResultRows(result *AgeRatingAuditResult) ([]string, [][]string) {
	headers := []string{"App ID", "Name", "Social Media", "Age Restricted", "Messaging & Chat", "Age Assurance", "Ready", "Missing"}
	rows := make([][]string, 0, len(result.Apps))
	for _, row := range result.Apps {
		missing := strings.Join(row.MissingResponses, ", ")
		if row.Error != "" {
			missing = "error: " + row.Error
		}
		rows = append(rows, []string{
			row.AppID,
			row.Name,
			row.SocialMedia,
			row.SocialMediaAgeRestricted,
			row.MessagingAndChat,
			row.AgeAssurance,
			strconv.FormatBool(row.Ready),
			missing,
		})
	}
	return headers, rows
}
