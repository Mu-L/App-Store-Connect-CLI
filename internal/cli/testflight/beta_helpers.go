package testflight

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

var errBetaTesterNotFound = errors.New("beta tester not found")

func resolveBetaGroupID(ctx context.Context, client *asc.Client, appID, group string) (string, error) {
	ids, err := resolveBetaGroupIDs(ctx, client, appID, []string{group})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

func resolveBetaGroupIDs(ctx context.Context, client *asc.Client, appID string, groupTokens []string) ([]string, error) {
	tokens := make([]string, 0, len(groupTokens))
	for _, token := range groupTokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		tokens = append(tokens, token)
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("beta group name is required")
	}

	groups, err := client.GetBetaGroups(ctx, appID, asc.WithBetaGroupsLimit(200))
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(tokens))
	for _, token := range tokens {
		id, err := matchBetaGroupID(groups, token)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func matchBetaGroupID(groups *asc.BetaGroupsResponse, group string) (string, error) {
	for _, item := range groups.Data {
		if item.ID == group {
			return item.ID, nil
		}
	}

	matches := make([]string, 0, 1)
	for _, item := range groups.Data {
		if strings.EqualFold(strings.TrimSpace(item.Attributes.Name), group) {
			matches = append(matches, item.ID)
		}
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("beta group %q not found", group)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("multiple beta groups named %q; use group ID", group)
	}
}

func findBetaTesterIDByEmail(ctx context.Context, client *asc.Client, appID, email string) (string, error) {
	testers, err := client.GetBetaTesters(ctx, appID, asc.WithBetaTestersEmail(email))
	if err != nil {
		return "", err
	}

	if len(testers.Data) == 0 {
		return "", errBetaTesterNotFound
	}
	if len(testers.Data) > 1 {
		return "", fmt.Errorf("multiple beta testers found for %q", strings.TrimSpace(email))
	}

	return testers.Data[0].ID, nil
}
