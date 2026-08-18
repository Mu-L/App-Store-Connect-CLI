package optimize

import (
	"context"
	"fmt"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

type resolvedSearchMetadata struct {
	AppID     string
	VersionID string
	Platform  string
	Metadata  searchMetadataSnapshot
}

func resolveSearchMetadata(ctx context.Context, appSelector, version, platform, locale string) (resolvedSearchMetadata, error) {
	client, err := shared.GetASCClient()
	if err != nil {
		return resolvedSearchMetadata{}, err
	}

	lookupCtx, cancel := shared.ContextWithTimeout(ctx)
	appID, err := shared.ResolveAppIDWithLookup(lookupCtx, client, appSelector)
	cancel()
	if err != nil {
		return resolvedSearchMetadata{}, fmt.Errorf("resolve app: %w", err)
	}

	versionCtx, cancel := shared.ContextWithTimeout(ctx)
	versionID, err := shared.ResolveAppStoreVersionID(versionCtx, client, appID, version, platform)
	cancel()
	if err != nil {
		return resolvedSearchMetadata{}, fmt.Errorf("resolve version: %w", err)
	}

	versionLocalizationCtx, cancel := shared.ContextWithTimeout(ctx)
	versionLocalizations, err := client.GetAppStoreVersionLocalizations(
		versionLocalizationCtx,
		versionID,
		asc.WithAppStoreVersionLocalizationLocales([]string{locale}),
		asc.WithAppStoreVersionLocalizationsLimit(2),
	)
	cancel()
	if err != nil {
		return resolvedSearchMetadata{}, fmt.Errorf("read version localization %q: %w", locale, err)
	}
	if versionLocalizations == nil || len(versionLocalizations.Data) == 0 {
		return resolvedSearchMetadata{}, fmt.Errorf("version localization %q not found", locale)
	}
	if len(versionLocalizations.Data) > 1 {
		return resolvedSearchMetadata{}, fmt.Errorf("multiple version localizations found for locale %q", locale)
	}

	appInfoCtx, cancel := shared.ContextWithTimeout(ctx)
	appInfoID, err := shared.ResolveAppInfoID(appInfoCtx, client, appID, "")
	cancel()
	if err != nil {
		return resolvedSearchMetadata{}, fmt.Errorf("resolve app info: %w", err)
	}

	appInfoLocalizationCtx, cancel := shared.ContextWithTimeout(ctx)
	appInfoLocalizations, err := client.GetAppInfoLocalizations(
		appInfoLocalizationCtx,
		appInfoID,
		asc.WithAppInfoLocalizationLocales([]string{locale}),
		asc.WithAppInfoLocalizationsLimit(2),
	)
	cancel()
	if err != nil {
		return resolvedSearchMetadata{}, fmt.Errorf("read app info localization %q: %w", locale, err)
	}
	if appInfoLocalizations == nil || len(appInfoLocalizations.Data) == 0 {
		return resolvedSearchMetadata{}, fmt.Errorf("app info localization %q not found", locale)
	}
	if len(appInfoLocalizations.Data) > 1 {
		return resolvedSearchMetadata{}, fmt.Errorf("multiple app info localizations found for locale %q", locale)
	}

	return resolvedSearchMetadata{
		AppID:     appID,
		VersionID: versionID,
		Platform:  platform,
		Metadata: searchMetadataSnapshot{
			Name:     strings.TrimSpace(appInfoLocalizations.Data[0].Attributes.Name),
			Subtitle: strings.TrimSpace(appInfoLocalizations.Data[0].Attributes.Subtitle),
			Keywords: strings.TrimSpace(versionLocalizations.Data[0].Attributes.Keywords),
		},
	}, nil
}
