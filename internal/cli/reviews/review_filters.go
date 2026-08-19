package reviews

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

const (
	reviewResponseStateAny         = "any"
	reviewResponseStateUnresponded = "unresponded"
	reviewResponseStateResponded   = "responded"
)

// reviewSorts lists the sort values Apple accepts on every customer review
// listing endpoint.
var reviewSorts = []string{"rating", "-rating", "createdDate", "-createdDate"}

// ReviewFilterFlags holds the customer review filter flags. Apple exposes the
// same filter, sort, and include surface on GET /v1/apps/{id}/customerReviews
// and GET /v1/appStoreVersions/{id}/customerReviews, so every command that
// lists customer reviews binds these flags from here and gets identical names,
// help text, and validation.
type ReviewFilterFlags struct {
	Stars           string
	Territory       string
	Sort            string
	ResponseState   string
	OnlyUnresponded bool
	IncludeResponse bool
	ResponseFields  string
}

// BindReviewFilterFlags registers the shared customer review filter flags on fs.
func BindReviewFilterFlags(fs *flag.FlagSet) *ReviewFilterFlags {
	filters := &ReviewFilterFlags{}
	fs.StringVar(&filters.Stars, "stars", "", "Filter by star ratings, comma-separated (1-5)")
	fs.StringVar(&filters.Territory, "territory", "", "Filter by territory (e.g., US, GBR)")
	fs.StringVar(&filters.Sort, "sort", "", "Sort by "+strings.Join(reviewSorts, ", "))
	fs.StringVar(&filters.ResponseState, "response-state", reviewResponseStateAny, "Filter by response state: any, unresponded/unreplied, responded/replied")
	fs.BoolVar(&filters.OnlyUnresponded, "only-unresponded", false, "Only list reviews without a published response")
	fs.BoolVar(&filters.IncludeResponse, "include-response", false, "Include customer review response relationships")
	fs.StringVar(&filters.ResponseFields, "response-fields", "", "Comma-separated customer review response fields: responseBody,lastModifiedDate,state,review")
	return filters
}

// ReviewOptions validates the bound flags and returns the matching query
// options. Invalid input is reported as a usage failure carrying the offending
// parameter so both review listings fail the same way.
func (f *ReviewFilterFlags) ReviewOptions() ([]asc.ReviewOption, error) {
	ratings, err := normalizeReviewStars(f.Stars)
	if err != nil {
		return nil, shared.WithDiagnostic(shared.UsageError(err.Error()), shared.DiagnosticInvalidInput, "--stars")
	}
	if err := shared.ValidateSort(f.Sort, reviewSorts...); err != nil {
		return nil, shared.WithDiagnostic(shared.NewValidationError(err), shared.DiagnosticInvalidInput, "--sort")
	}
	responseState, err := normalizeReviewResponseState(f.ResponseState)
	if err != nil {
		return nil, shared.WithDiagnostic(shared.UsageError(err.Error()), shared.DiagnosticInvalidInput, "--response-state")
	}
	if f.OnlyUnresponded {
		if responseState == reviewResponseStateResponded {
			return nil, shared.WithDiagnostic(shared.UsageError("--only-unresponded cannot be combined with --response-state responded"), shared.DiagnosticConflictingInput, "")
		}
		responseState = reviewResponseStateUnresponded
	}
	responseFields, err := normalizeReviewResponseFields(f.ResponseFields)
	if err != nil {
		return nil, shared.WithDiagnostic(shared.UsageError(err.Error()), shared.DiagnosticInvalidInput, "--response-fields")
	}

	opts := []asc.ReviewOption{
		asc.WithRatings(ratings),
		asc.WithTerritory(f.Territory),
	}
	if strings.TrimSpace(f.Sort) != "" {
		opts = append(opts, asc.WithReviewSort(f.Sort))
	}
	if exists, ok := publishedResponseExistsFilter(responseState); ok {
		opts = append(opts, asc.WithPublishedResponseExists(exists))
	}
	if f.IncludeResponse {
		opts = append(opts, asc.WithReviewIncludeResponse())
	}
	if len(responseFields) > 0 {
		opts = append(opts, asc.WithReviewIncludeResponse(), asc.WithReviewResponseFields(responseFields))
	}
	return opts, nil
}

func normalizeReviewResponseState(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		normalized = reviewResponseStateAny
	}
	switch normalized {
	case reviewResponseStateAny, reviewResponseStateUnresponded, reviewResponseStateResponded:
		return normalized, nil
	case "unreplied":
		return reviewResponseStateUnresponded, nil
	case "replied":
		return reviewResponseStateResponded, nil
	default:
		return "", fmt.Errorf("--response-state must be one of: any, unresponded, unreplied, responded, replied")
	}
}

// normalizeReviewStars parses the comma-separated --stars value. Apple accepts
// filter[rating] as an array parameter, so callers can ask for several ratings
// in one request. An empty value means "no rating filter"; anything else must
// be a list where every element is a rating between 1 and 5. Empty elements
// (`1,,2`, `1,`) are rejected rather than skipped, so malformed input never
// silently narrows the filter.
func normalizeReviewStars(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	elements := strings.Split(value, ",")
	ratings := make([]int, 0, len(elements))
	for _, element := range elements {
		rating, err := strconv.Atoi(strings.TrimSpace(element))
		if err != nil || rating < 1 || rating > 5 {
			return nil, errInvalidReviewStars()
		}
		ratings = append(ratings, rating)
	}
	return ratings, nil
}

func errInvalidReviewStars() error {
	return fmt.Errorf("--stars must be a comma-separated list of star ratings: 1, 2, 3, 4, 5")
}

// normalizeReviewResponseFields parses the comma-separated --response-fields
// value. An empty value means "no sparse fieldset"; anything else must be a
// list where every element names a customer review response field. Empty
// elements (`responseBody,,state`, `,`) are rejected rather than skipped, so
// malformed input never silently changes or drops the fieldset.
func normalizeReviewResponseFields(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	allowed := map[string]bool{
		"responseBody":     true,
		"lastModifiedDate": true,
		"state":            true,
		"review":           true,
	}
	fields := strings.Split(value, ",")
	normalized := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if !allowed[field] {
			return nil, fmt.Errorf("--response-fields must be a comma-separated list of: responseBody,lastModifiedDate,state,review")
		}
		normalized = append(normalized, field)
	}
	return normalized, nil
}

func publishedResponseExistsFilter(responseState string) (bool, bool) {
	switch responseState {
	case reviewResponseStateUnresponded:
		return false, true
	case reviewResponseStateResponded:
		return true, true
	default:
		return false, false
	}
}
