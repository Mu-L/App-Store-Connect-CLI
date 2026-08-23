package gamecenter

import (
	"context"
	"errors"
	"flag"
	"testing"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func TestGameCenterGroupRelationshipReplacementsRequireConfirm(t *testing.T) {
	isolateGameCenterAuthEnv(t)

	commands := map[string]func() *ffcli.Command{
		"achievements": GameCenterGroupAchievementsSetCommand,
		"leaderboards": GameCenterGroupLeaderboardsSetCommand,
	}

	for name, newCommand := range commands {
		for _, v2 := range []bool{false, true} {
			t.Run(name+" v2="+boolString(v2), func(t *testing.T) {
				cmd := newCommand()
				args := []string{"--group-id", "group-1", "--ids", "resource-1"}
				if v2 {
					args = append(args, "--v2")
				}
				if err := cmd.FlagSet.Parse(args); err != nil {
					t.Fatalf("parse flags: %v", err)
				}

				var err error
				stderr := captureGameCenterStderr(t, func() {
					err = cmd.Exec(context.Background(), []string{})
				})
				if !errors.Is(err, flag.ErrHelp) {
					t.Fatalf("replacement without --confirm should fail validation before auth, got %v", err)
				}
				if err.Error() != "--confirm" {
					t.Fatalf("error = %q, want missing parameter %q", err.Error(), "--confirm")
				}
				want := "Error: --confirm is required to replace group " + name + " relationships\n"
				if stderr != want {
					t.Fatalf("stderr = %q, want %q", stderr, want)
				}
			})
		}
	}
}

func TestGameCenterGroupRelationshipReplacementConfirmPassesValidation(t *testing.T) {
	isolateGameCenterAuthEnv(t)

	commands := map[string]func() *ffcli.Command{
		"achievements": GameCenterGroupAchievementsSetCommand,
		"leaderboards": GameCenterGroupLeaderboardsSetCommand,
	}

	for name, newCommand := range commands {
		for _, v2 := range []bool{false, true} {
			t.Run(name+" v2="+boolString(v2), func(t *testing.T) {
				cmd := newCommand()
				args := []string{"--group-id", "group-1", "--ids", "resource-1", "--confirm"}
				if v2 {
					args = append(args, "--v2")
				}
				if err := cmd.FlagSet.Parse(args); err != nil {
					t.Fatalf("parse flags: %v", err)
				}

				err := cmd.Exec(context.Background(), []string{})
				if errors.Is(err, flag.ErrHelp) {
					t.Fatalf("replacement with --confirm should pass validation before auth, got %v", err)
				}
			})
		}
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
