package web

import (
	"flag"
	"fmt"
	"os"
	"strings"

	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

const developerTeamFlagUsage = "Developer Portal team ID (or exact team name) to use; required when the Apple Account belongs to multiple Developer Portal teams and none matches the selected App Store Connect provider"

type developerPortalFlags struct {
	developerTeam *string
}

func bindDeveloperPortalFlags(fs *flag.FlagSet) developerPortalFlags {
	return bindDeveloperPortalFlagsWithUsage(fs, developerTeamFlagUsage)
}

func bindDeveloperPortalFlagsExperimental(fs *flag.FlagSet) developerPortalFlags {
	return bindDeveloperPortalFlagsWithUsage(fs, "[experimental] "+developerTeamFlagUsage)
}

func bindDeveloperPortalFlagsWithUsage(fs *flag.FlagSet, usage string) developerPortalFlags {
	return developerPortalFlags{
		developerTeam: fs.String("developer-team", "", usage),
	}
}

func newDeveloperPortalClient(session *webcore.AuthSession, flags developerPortalFlags) *webcore.Client {
	client := newWebClientFn(session)
	if client == nil {
		return nil
	}
	if flags.developerTeam != nil {
		client.SetDeveloperTeamSelector(strings.TrimSpace(*flags.developerTeam))
	}
	return client
}

func persistDeveloperPortalSession(session *webcore.AuthSession) {
	if err := persistWebSessionFn(session); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Warning: failed to persist refreshed web session: %v\n", err)
	}
}
