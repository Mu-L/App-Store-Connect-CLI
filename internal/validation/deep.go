package validation

import (
	"net/url"
	"strings"
)

// SummarizeDeepChecks counts deep checks by terminal status.
func SummarizeDeepChecks(checks []DeepCheck) DeepSummary {
	summary := DeepSummary{}
	for _, check := range checks {
		switch check.Status {
		case DeepStatusPassed:
			summary.Passed++
		case DeepStatusBlocked:
			summary.Blocked++
		case DeepStatusUnverified:
			summary.Unverified++
		case DeepStatusNotApplicable:
			summary.NotApplicable++
		}
	}
	return summary
}

// ApplyDeepValidation merges deep evidence into a public readiness report and
// rebuilds all derived counts and remediation steps.
func ApplyDeepValidation(report Report, deep DeepReport, findings []CheckResult) Report {
	checks := make([]CheckResult, 0, len(report.Checks)+len(findings))
	for _, check := range report.Checks {
		if check.ID == privacyPublishStateUnverifiedID {
			continue
		}
		checks = append(checks, check)
	}
	checks = append(checks, findings...)

	for index := range checks {
		if checks[index].Resolution != nil {
			continue
		}
		if strings.TrimSpace(checks[index].Remediation) == "" && checks[index].Severity == SeverityInfo {
			continue
		}
		checks[index].Resolution = defaultManualResolution(report.AppID, checks[index].ID)
	}

	deep.Summary = SummarizeDeepChecks(deep.Checks)
	report.Checks = checks
	report.Summary = summarize(checks, report.Strict)
	report.Remediation = BuildRemediation(checks, report.Strict)
	report.Deep = &deep
	return report
}

func defaultManualResolution(appID, checkID string) *Resolution {
	appURL := appStoreConnectAppURL(appID, "")
	switch {
	case strings.HasPrefix(checkID, "availability."), strings.HasPrefix(checkID, "pricing."):
		appURL = appStoreConnectAppURL(appID, "appstore/pricing")
	case strings.HasPrefix(checkID, "review_details."):
		appURL = appStoreConnectAppURL(appID, "appstore/review")
	case strings.HasPrefix(checkID, "privacy."):
		appURL = appStoreConnectAppURL(appID, "appPrivacy")
	}
	return &Resolution{
		Fixability:         FixabilityManual,
		AppStoreConnectURL: appURL,
	}
}

func appStoreConnectAppURL(appID, suffix string) string {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return ""
	}
	base := "https://appstoreconnect.apple.com/apps/" + url.PathEscape(appID)
	if strings.TrimSpace(suffix) == "" {
		return base
	}
	return base + "/" + strings.TrimPrefix(strings.TrimSpace(suffix), "/")
}
