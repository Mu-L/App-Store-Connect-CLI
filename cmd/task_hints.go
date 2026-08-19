package cmd

import (
	"fmt"
	"os"
)

// taskHint is one curated entry of a command group's "Common tasks" map.
type taskHint struct {
	task    string
	command string
}

// unknownChildTaskHints maps a fully qualified command group to the handful of
// tasks callers most often reach for there. The nearest-match suggester already
// recovers typos; these hints answer the other failure mode, where a caller
// guesses a verb the group never had (`asc builds latest`, `asc builds status`)
// and the bare unknown-command error offers nothing to act on.
//
// Every command must be a copy-paste valid invocation of a real leaf command in
// the group, using long-form flags that command defines. Tests in
// task_hints_test.go resolve each entry against the live command tree, so keep
// the table in sync with the commands themselves rather than with memory.
//
// Prefer the canonical first-class command for a task over a generic equivalent
// that happens to produce the same answer: `asc builds info --app X --latest`
// rather than a sorted single-result list, and `asc builds next-build-number`
// rather than arithmetic on a listing.
var unknownChildTaskHints = map[string][]taskHint{
	"asc apps": {
		{task: "list apps", command: "asc apps list"},
		{task: "find by bundle ID", command: "asc apps list --bundle-id <bundle-id>"},
		{task: "view one app", command: "asc apps view --id <app-id>"},
		{task: "view app metadata", command: "asc apps info view --app <app-id>"},
	},
	"asc auth": {
		{task: "check credentials", command: "asc auth status"},
		{task: "diagnose problems", command: "asc auth doctor"},
		{task: "switch profile", command: "asc auth switch --name <profile>"},
		{
			task:    "store an API key",
			command: "asc auth login --name <name> --key-id <key-id> --issuer-id <issuer-id> --private-key <path>",
		},
	},
	"asc builds": {
		{task: "list builds", command: "asc builds list --app <app-id>"},
		{task: "latest build", command: "asc builds info --app <app-id> --latest"},
		{task: "next build number", command: "asc builds next-build-number --app <app-id>"},
		{task: "upload a build", command: "asc builds upload --app <app-id> --ipa <path>"},
		{task: "wait for processing", command: "asc builds wait --app <app-id> --latest"},
	},
	"asc iap": {
		{task: "list purchases", command: "asc iap list --app <app-id>"},
		{task: "view a purchase", command: "asc iap view --id <iap-id>"},
		{task: "list versions", command: "asc iap versions list --iap-id <iap-id>"},
		{task: "pricing summary", command: "asc iap pricing summary --app <app-id>"},
	},
	"asc review": {
		{task: "review status", command: "asc review status --app <app-id>"},
		{task: "explain blockers", command: "asc review doctor --app <app-id>"},
		{
			task:    "submit for review",
			command: "asc review submit --app <app-id> --version <version> --build <build-id> --confirm",
		},
		{task: "past submissions", command: "asc review history --app <app-id>"},
	},
	"asc subscriptions": {
		{task: "list groups", command: "asc subscriptions groups list --app <app-id>"},
		{task: "list subscriptions", command: "asc subscriptions list --app <app-id>"},
		{task: "view a subscription", command: "asc subscriptions view --id <subscription-id>"},
		{task: "pricing summary", command: "asc subscriptions pricing summary --app <app-id>"},
	},
	"asc testflight": {
		{task: "list beta groups", command: "asc testflight groups list --app <app-id>"},
		{task: "list testers", command: "asc testflight testers list --app <app-id>"},
		{task: "read feedback", command: "asc testflight feedback list --app <app-id>"},
		{task: "notify testers", command: "asc testflight notifications send --build-id <build-id>"},
	},
	"asc testflight groups": {
		{task: "list groups", command: "asc testflight groups list --app <app-id>"},
		{task: "view a group", command: "asc testflight groups view --id <group-id>"},
		{task: "create a group", command: "asc testflight groups create --app <app-id> --name <name>"},
		{
			task:    "add testers",
			command: "asc testflight groups add-testers --group <group-id> --email <email>",
		},
	},
	"asc versions": {
		{task: "list versions", command: "asc versions list --app <app-id>"},
		{task: "view a version", command: "asc versions view --version-id <version-id>"},
		{task: "create a version", command: "asc versions create --app <app-id> --version <version>"},
		{
			task:    "attach a build",
			command: "asc versions attach-build --version-id <version-id> --build-id <build-id>",
		},
		{task: "release a version", command: "asc versions release --version-id <version-id> --confirm"},
	},
}

// printUnknownChildTaskHints writes the curated task map for a command group,
// or nothing when the group has no curated entries. Callers print it after the
// error line and before the help pointer, so the error stays the first thing on
// stderr and the exit code is unaffected.
func printUnknownChildTaskHints(commandName string) {
	hints := unknownChildTaskHints[commandName]
	if len(hints) == 0 {
		return
	}

	width := 0
	for _, hint := range hints {
		if len(hint.task) > width {
			width = len(hint.task)
		}
	}

	fmt.Fprintln(os.Stderr, "Common tasks:")
	for _, hint := range hints {
		fmt.Fprintf(os.Stderr, "  %-*s  %s\n", width, hint.task, hint.command)
	}
}
