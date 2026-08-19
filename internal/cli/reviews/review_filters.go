package reviews

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	reviewResponseStateAny         = "any"
	reviewResponseStateUnresponded = "unresponded"
	reviewResponseStateResponded   = "responded"
)

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
// resolve to at least one rating between 1 and 5.
func normalizeReviewStars(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	elements := strings.Split(value, ",")
	ratings := make([]int, 0, len(elements))
	for _, element := range elements {
		element = strings.TrimSpace(element)
		if element == "" {
			continue
		}
		rating, err := strconv.Atoi(element)
		if err != nil || rating < 1 || rating > 5 {
			return nil, errInvalidReviewStars()
		}
		ratings = append(ratings, rating)
	}
	if len(ratings) == 0 {
		return nil, errInvalidReviewStars()
	}
	return ratings, nil
}

func errInvalidReviewStars() error {
	return fmt.Errorf("--stars must be a comma-separated list of star ratings: 1, 2, 3, 4, 5")
}

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
		if field == "" {
			continue
		}
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
