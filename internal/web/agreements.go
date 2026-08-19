package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	developerPortalAgreementHistoryPath = "/services-account/QH65B2/account/getAgreementHistory"
	developerPortalAcceptAgreementsPath = "/services-account/QH65B2/account/acceptAgreements"
	olympusContractMessagesPath         = "/contractMessages"
)

// ContractMessage is one App Store Connect alert banner entry, such as the
// "Apple Developer Program License Agreement Updated" warning.
type ContractMessage struct {
	ID      string `json:"id"`
	Group   string `json:"group"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

// Agreement summarizes one Apple Developer Program agreement record.
type Agreement struct {
	AgreementID               string `json:"agreementId"`
	Title                     string `json:"title"`
	Status                    string `json:"status"`
	Version                   string `json:"version"`
	IsProgramLicenseAgreement bool   `json:"isProgramLicenseAgreement"`
	Pending                   bool   `json:"pending"`
	DateEffective             string `json:"dateEffective,omitempty"`
	DateAccepted              string `json:"dateAccepted,omitempty"`
	DateAgreeBy               string `json:"dateAgreeBy,omitempty"`
	DownloadURL               string `json:"downloadUrl,omitempty"`
}

// AgreementsStatusResult reports pending and accepted Apple Developer Program
// agreements for the web session's team.
type AgreementsStatusResult struct {
	TeamID           string            `json:"teamId"`
	Pending          bool              `json:"pending"`
	ContractMessages []ContractMessage `json:"contractMessages"`
	Agreements       []Agreement       `json:"agreements"`
}

// AgreementsAcceptRequest accepts one or more Developer Portal agreements.
type AgreementsAcceptRequest struct {
	AgreementIDs []string
}

// AgreementsAcceptResult summarizes an agreement acceptance.
type AgreementsAcceptResult struct {
	TeamID       string      `json:"teamId"`
	AgreementIDs []string    `json:"agreementIds"`
	Status       string      `json:"status"`
	Agreements   []Agreement `json:"agreements"`
}

// developerAgreementsEnvelope is the QH65B2 account services response shape.
// These endpoints answer HTTP 200 even for failures; resultCode carries the
// outcome (0 success; for example 3050 missing team, 3100 unknown team).
type developerAgreementsEnvelope struct {
	ResultCode   int                        `json:"resultCode"`
	ResultString string                     `json:"resultString"`
	UserString   string                     `json:"userString"`
	Agreements   []developerAgreementRecord `json:"agreements"`
}

type developerAgreementRecord struct {
	AgreementID          string `json:"agreementId"`
	Title                string `json:"title"`
	Status               string `json:"status"`
	Version              string `json:"version"`
	DateEffective        int64  `json:"dateEffective"`
	DateAccepted         int64  `json:"dateAccepted"`
	DateAgreeBy          int64  `json:"dateAgreeBy"`
	IsAgreementPLA       bool   `json:"isAgreementPLA"`
	AgreementDownloadURL string `json:"agreementDownloadUrl"`
}

// GetAgreementsStatus reports the App Store Connect agreement banner and the
// team's Developer Portal agreement history in one pending-aware summary.
func (c *Client) GetAgreementsStatus(ctx context.Context) (*AgreementsStatusResult, error) {
	messages, err := c.getContractMessages(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.ensureDeveloperPortalSession(ctx); err != nil {
		return nil, err
	}
	teamID := c.developerPortalTeamID()
	if teamID == "" {
		return nil, fmt.Errorf("developer portal team is not selected; %s", developerPortalAuthHint)
	}
	envelope, err := c.doDeveloperPortalAgreementsRequest(ctx, developerPortalAgreementHistoryPath, map[string]string{"teamId": teamID})
	if err != nil {
		return nil, err
	}

	agreements := make([]Agreement, 0, len(envelope.Agreements))
	pending := len(messages) > 0
	for _, record := range envelope.Agreements {
		agreement := c.newAgreement(record)
		if agreement.Pending {
			pending = true
		}
		agreements = append(agreements, agreement)
	}
	return &AgreementsStatusResult{
		TeamID:           teamID,
		Pending:          pending,
		ContractMessages: messages,
		Agreements:       agreements,
	}, nil
}

// AcceptAgreements accepts the given Developer Portal agreements for the web
// session's team. Apple only allows the Account Holder to accept agreements.
func (c *Client) AcceptAgreements(ctx context.Context, req AgreementsAcceptRequest) (*AgreementsAcceptResult, error) {
	agreementIDs := make([]string, 0, len(req.AgreementIDs))
	for _, id := range req.AgreementIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			agreementIDs = append(agreementIDs, id)
		}
	}
	if len(agreementIDs) == 0 {
		return nil, fmt.Errorf("at least one agreement id is required")
	}

	if err := c.ensureDeveloperPortalSession(ctx); err != nil {
		return nil, err
	}
	teamID := c.developerPortalTeamID()
	if teamID == "" {
		return nil, fmt.Errorf("developer portal team is not selected; %s", developerPortalAuthHint)
	}
	payload := struct {
		TeamID       string   `json:"teamId"`
		AgreementIDs []string `json:"agreementIds"`
	}{TeamID: teamID, AgreementIDs: agreementIDs}
	envelope, err := c.doDeveloperPortalAgreementsRequest(ctx, developerPortalAcceptAgreementsPath, payload)
	if err != nil {
		return nil, err
	}

	agreements := make([]Agreement, 0, len(envelope.Agreements))
	for _, record := range envelope.Agreements {
		agreements = append(agreements, c.newAgreement(record))
	}
	return &AgreementsAcceptResult{
		TeamID:       teamID,
		AgreementIDs: agreementIDs,
		Status:       "accepted",
		Agreements:   agreements,
	}, nil
}

func (c *Client) getContractMessages(ctx context.Context) ([]ContractMessage, error) {
	body, err := c.doOlympusGet(ctx, olympusContractMessagesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch App Store Connect contract messages: %w", err)
	}
	var messages []ContractMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		return nil, fmt.Errorf("failed to parse App Store Connect contract messages: %w", err)
	}
	return messages, nil
}

func (c *Client) doDeveloperPortalAgreementsRequest(ctx context.Context, path string, payload any) (*developerAgreementsEnvelope, error) {
	headers := developerPortalAgreementsHeaders()
	csrf, csrfTS := c.developerCSRFTokens()
	if csrf != "" {
		headers.Set("csrf", csrf)
	}
	if csrfTS != "" {
		headers.Set("csrf_ts", csrfTS)
	}
	body, response, err := c.doDeveloperPortalHTTP(ctx, http.MethodPost, c.developerPortalOrigin()+path, payload, headers)
	if err != nil {
		return nil, err
	}
	c.captureDeveloperCSRFTokens(response.Header)
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, developerPortalSessionError(response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &APIError{
			Status:         response.StatusCode,
			AppleRequestID: extractAppleRequestID(response.Header),
			CorrelationKey: strings.TrimSpace(response.Header.Get("X-Apple-Jingle-Correlation-Key")),
			rawBody:        body,
		}
	}
	var envelope developerAgreementsEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse Developer Portal agreements response: %w", err)
	}
	if envelope.ResultCode != 0 {
		message := strings.TrimSpace(envelope.UserString)
		if message == "" {
			message = strings.TrimSpace(envelope.ResultString)
		}
		if message == "" {
			message = "unknown Developer Portal error"
		}
		return nil, fmt.Errorf("developer portal agreements request failed (resultCode %d): %s", envelope.ResultCode, message)
	}
	return &envelope, nil
}

func (c *Client) newAgreement(record developerAgreementRecord) Agreement {
	downloadURL := strings.TrimSpace(record.AgreementDownloadURL)
	if downloadURL != "" && strings.HasPrefix(downloadURL, "/") {
		downloadURL = c.developerPortalOrigin() + downloadURL
	}
	return Agreement{
		AgreementID:               strings.TrimSpace(record.AgreementID),
		Title:                     strings.TrimSpace(record.Title),
		Status:                    strings.TrimSpace(record.Status),
		Version:                   strings.TrimSpace(record.Version),
		IsProgramLicenseAgreement: record.IsAgreementPLA,
		Pending:                   record.DateAccepted < record.DateEffective,
		DateEffective:             formatAgreementDate(record.DateEffective),
		DateAccepted:              formatAgreementDate(record.DateAccepted),
		DateAgreeBy:               formatAgreementDate(record.DateAgreeBy),
		DownloadURL:               downloadURL,
	}
}

func formatAgreementDate(milliseconds int64) string {
	if milliseconds <= 0 {
		return ""
	}
	return time.UnixMilli(milliseconds).UTC().Format(time.RFC3339)
}

func developerPortalAgreementsHeaders() http.Header {
	headers := make(http.Header)
	headers.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	headers.Set("Content-Type", "application/json")
	headers.Set("Referer", developerPortalBaseURL+"/account")
	headers.Set("User-Agent", "App-Store-Connect-CLI")
	headers.Set("X-Requested-With", "XMLHttpRequest")
	return headers
}
