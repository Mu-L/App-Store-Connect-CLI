package search

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared/suggest"
)

const (
	defaultLimit           = 10
	canonicalIntentBoost   = 300
	exactPathTokenScore    = 60
	compoundPathTokenScore = 30
	exactLeafCommandBoost  = 40
)

var tokenPattern = regexp.MustCompile(`[a-z0-9][a-z0-9-]*`)

// SearchResponse is the machine-readable output for command discovery.
type SearchResponse struct {
	Query   string         `json:"query"`
	Count   int            `json:"count"`
	Results []SearchResult `json:"results"`
}

// SearchResult describes a matching CLI command.
type SearchResult struct {
	Command  string   `json:"command"`
	Summary  string   `json:"summary"`
	Usage    string   `json:"usage,omitempty"`
	Score    int      `json:"score"`
	Matched  []string `json:"matched"`
	Examples []string `json:"examples,omitempty"`
}

type commandDoc struct {
	Command       string
	Summary       string
	Usage         string
	Examples      []string
	PathTokens    []string
	SummaryTokens []string
	UsageTokens   []string
	ExampleTokens []string
	HelpTokens    []string
	TextTokens    []string
	FlagTokens    []string
	AllTokens     []string
	CommandRank   int
}

type canonicalIntentRule struct {
	command  string
	actions  []string
	subjects []string
	reason   string
}

type authActionScope struct {
	queryToken    string
	commandPrefix string
	reasonPrefix  string
	actions       []string
}

var canonicalIntentRules = []canonicalIntentRule{
	{
		command:  "asc publish appstore",
		actions:  []string{"ship", "shipping", "publish", "release", "submit", "submission", "upload"},
		subjects: []string{"app", "appstore", "store"},
		reason:   "canonical:appstore-publish",
	},
	{
		command:  "asc publish testflight",
		actions:  []string{"ship", "shipping", "publish", "release", "distribute", "distribution", "upload"},
		subjects: []string{"beta", "testflight"},
		reason:   "canonical:testflight-publish",
	},
}

var authActionScopes = []authActionScope{
	{
		queryToken:    "storekit",
		commandPrefix: "asc storekit auth",
		reasonPrefix:  "canonical:storekit-auth",
		actions:       []string{"login", "switch", "doctor", "logout"},
	},
	{
		queryToken:    "ads",
		commandPrefix: "asc ads auth",
		reasonPrefix:  "canonical:ads-auth",
		actions:       []string{"login", "discover", "switch", "token", "doctor", "logout"},
	},
	{
		queryToken:    "web",
		commandPrefix: "asc web auth",
		reasonPrefix:  "canonical:web-auth",
		actions:       []string{"login", "capabilities", "logout"},
	},
	{
		commandPrefix: "asc auth",
		reasonPrefix:  "canonical:auth",
		actions:       []string{"init", "login", "export-to-config", "export", "switch", "logout", "doctor", "issuer-id", "token"},
	},
}

type scoredResult struct {
	result SearchResult
	rank   int
}

// SearchCommand returns the command-discovery search command.
func SearchCommand(commands func() []*ffcli.Command) *ffcli.Command {
	fs := flag.NewFlagSet("search", flag.ExitOnError)
	output := shared.BindOutputFlags(fs)
	limit := fs.Int("limit", defaultLimit, "Maximum number of results to return")

	return &ffcli.Command{
		Name:       "search",
		ShortUsage: "asc search [flags] <query>",
		ShortHelp:  "Search asc commands and examples for agent-oriented command discovery.",
		LongHelp: `Search asc commands and examples for agent-oriented command discovery.

Search is local and deterministic. It indexes the registered command tree,
including command paths, summaries, usage strings, examples, and flag names.
It does not search App Store Connect data.

Examples:
  asc search "external testers"
  asc search --output json "submit app for review"
  asc search --output table "upload build"
  asc search --limit 5 "cert profiles"`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			_ = ctx
			defer resetFlagSet(fs)

			args, err := parseInterspersedSearchFlags(fs, args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return flag.ErrHelp
			}
			if len(args) == 0 {
				fmt.Fprintln(os.Stderr, "Error: search query is required")
				return shared.MissingRequiredUsageError("")
			}
			if *limit <= 0 {
				fmt.Fprintln(os.Stderr, "Error: --limit must be greater than 0")
				return flag.ErrHelp
			}

			query := strings.Join(args, " ")
			if strings.TrimSpace(query) == "" {
				fmt.Fprintln(os.Stderr, "Error: search query is required")
				return shared.MissingRequiredUsageError("")
			}
			selectedOutput := *output.Output
			selectedPretty := *output.Pretty
			selectedLimit := *limit

			response := SearchCommands(commands(), query, selectedLimit)
			if err := shared.PrintOutputWithRenderers(
				response,
				selectedOutput,
				selectedPretty,
				func() error {
					asc.RenderTable([]string{"score", "command", "summary", "matched"}, searchRows(response.Results))
					return nil
				},
				func() error {
					asc.RenderMarkdown([]string{"score", "command", "summary", "matched"}, searchRows(response.Results))
					return nil
				},
			); err != nil {
				return shared.UsageError(err.Error())
			}
			return nil
		},
	}
}

func resetFlagSet(fs *flag.FlagSet) {
	if fs == nil {
		return
	}
	fs.VisitAll(func(f *flag.Flag) {
		if f == nil {
			return
		}
		_ = f.Value.Set(f.DefValue)
	})
}

func parseInterspersedSearchFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	if fs == nil || len(args) == 0 {
		return args, nil
	}

	queryArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			queryArgs = append(queryArgs, args[i+1:]...)
			break
		}

		name, value, hasValue, ok := splitSearchFlagArg(arg)
		if !ok {
			queryArgs = append(queryArgs, arg)
			continue
		}

		f := fs.Lookup(name)
		if f == nil {
			queryArgs = append(queryArgs, arg)
			continue
		}

		if isBoolSearchFlag(f) && !hasValue {
			if err := f.Value.Set("true"); err != nil {
				return nil, fmt.Errorf("invalid value %q for --%s: %w", "true", name, err)
			}
			continue
		}

		if !hasValue {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag needs an argument: --%s", name)
			}
			i++
			value = args[i]
		}

		if err := f.Value.Set(value); err != nil {
			return nil, fmt.Errorf("invalid value %q for --%s: %w", value, name, err)
		}
	}

	return queryArgs, nil
}

func splitSearchFlagArg(arg string) (name, value string, hasValue, ok bool) {
	if arg == "" || arg == "-" || !strings.HasPrefix(arg, "-") {
		return "", "", false, false
	}

	trimmed := strings.TrimPrefix(arg, "--")
	if trimmed == arg {
		trimmed = strings.TrimPrefix(arg, "-")
	}
	if trimmed == "" {
		return "", "", false, false
	}

	name, value, hasValue = strings.Cut(trimmed, "=")
	if name == "" {
		return "", "", false, false
	}
	return name, value, hasValue, true
}

func isBoolSearchFlag(f *flag.Flag) bool {
	type boolFlag interface {
		IsBoolFlag() bool
	}

	if f == nil {
		return false
	}
	boolValue, ok := f.Value.(boolFlag)
	return ok && boolValue.IsBoolFlag()
}

// SearchCommands searches a command tree and returns ranked results.
func SearchCommands(commands []*ffcli.Command, query string, limit int) SearchResponse {
	normalizedQuery := normalizeQuery(query)
	if limit <= 0 {
		limit = defaultLimit
	}
	docs := collectCommandDocs(commands)
	scored := scoreCommandDocs(docs, normalizedQuery)
	if len(scored) > limit {
		scored = scored[:limit]
	}

	results := make([]SearchResult, 0, len(scored))
	for _, item := range scored {
		results = append(results, item.result)
	}
	return SearchResponse{
		Query:   normalizedQuery,
		Count:   len(results),
		Results: results,
	}
}

func collectCommandDocs(commands []*ffcli.Command) []commandDoc {
	docs := make([]commandDoc, 0)
	for _, cmd := range commands {
		collectCommandDoc(&docs, cmd, nil)
	}
	return docs
}

func collectCommandDoc(docs *[]commandDoc, cmd *ffcli.Command, parents []string) {
	if cmd == nil || hiddenCommand(cmd) {
		return
	}

	pathParts := append(append([]string{"asc"}, parents...), cmd.Name)
	command := strings.Join(pathParts, " ")
	usage := strings.TrimSpace(cmd.ShortUsage)
	if usage == "" {
		usage = command
	}
	summary := strings.TrimSpace(cmd.ShortHelp)
	longHelp := strings.TrimSpace(cmd.LongHelp)
	examples := extractExamples(longHelp)
	flags := commandFlags(cmd)
	pathTokens := uniqueTokens(strings.Join(pathParts[1:], " "))
	summaryTokens := uniqueTokens(summary)
	usageTokens := uniqueTokens(usage)
	exampleTokens := uniqueTokens(strings.Join(examples, " "))
	helpTokens := uniqueTokens(longHelp)
	textTokens := append([]string{}, summaryTokens...)
	textTokens = append(textTokens, usageTokens...)
	textTokens = append(textTokens, exampleTokens...)
	textTokens = uniqueStrings(append(textTokens, helpTokens...))
	flagTokens := uniqueTokens(strings.Join(flags, " "))

	all := append(append(append([]string{}, pathTokens...), textTokens...), flagTokens...)
	*docs = append(*docs, commandDoc{
		Command:       command,
		Summary:       summary,
		Usage:         usage,
		Examples:      examples,
		PathTokens:    pathTokens,
		SummaryTokens: summaryTokens,
		UsageTokens:   usageTokens,
		ExampleTokens: exampleTokens,
		HelpTokens:    helpTokens,
		TextTokens:    textTokens,
		FlagTokens:    flagTokens,
		AllTokens:     uniqueStrings(all),
		CommandRank:   len(pathParts),
	})

	nextParents := append(append([]string{}, parents...), cmd.Name)
	for _, sub := range cmd.Subcommands {
		collectCommandDoc(docs, sub, nextParents)
	}
}

func scoreCommandDocs(docs []commandDoc, query string) []scoredResult {
	queryTokens := dropLeadingRootToken(uniqueTokens(query))
	if len(queryTokens) == 0 {
		return nil
	}

	results := make([]scoredResult, 0)
	for _, doc := range docs {
		score, matched := scoreCommandDoc(doc, queryTokens)
		if score <= 0 {
			continue
		}
		results = append(results, scoredResult{
			result: SearchResult{
				Command:  doc.Command,
				Summary:  doc.Summary,
				Usage:    doc.Usage,
				Score:    score,
				Matched:  matched,
				Examples: doc.Examples,
			},
			rank: doc.CommandRank,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].result.Score != results[j].result.Score {
			return results[i].result.Score > results[j].result.Score
		}
		if results[i].rank != results[j].rank {
			return results[i].rank < results[j].rank
		}
		return results[i].result.Command < results[j].result.Command
	})
	return results
}

func dropLeadingRootToken(tokens []string) []string {
	if len(tokens) == 0 || tokens[0] != "asc" {
		return tokens
	}
	return tokens[1:]
}

func scoreCommandDoc(doc commandDoc, queryTokens []string) (int, []string) {
	score := 0
	reasons := make([]string, 0)
	seenReasons := make(map[string]struct{})

	for _, token := range queryTokens {
		tokenScore, tokenReasons := scoreTerm(doc, token, "query:"+token)
		score += tokenScore
		for _, reason := range tokenReasons {
			addReason(&reasons, seenReasons, reason)
		}

		for _, alias := range aliasesFor(token) {
			if sameSearchStem(alias, token) {
				continue
			}
			aliasScore, aliasReasons := scoreTerm(doc, alias, "alias:"+token)
			if aliasScore == 0 {
				continue
			}
			score += max(1, aliasScore/2)
			addReason(&reasons, seenReasons, "alias:"+token)
			for _, reason := range aliasReasons {
				addReason(&reasons, seenReasons, reason)
			}
		}
	}
	if len(queryTokens) > 1 {
		if leafToken, ok := exactLeafQueryToken(doc.Command, queryTokens); ok && hasSupportingQueryToken(doc, queryTokens, leafToken) {
			score += exactLeafCommandBoost
			addReason(&reasons, seenReasons, "command-leaf:"+leafToken)
		}
	}

	if boost, reason := canonicalBoostFor(doc.Command, queryTokens); boost > 0 {
		score += boost
		addReason(&reasons, seenReasons, reason)
	}

	return score, reasons
}

func scoreTerm(doc commandDoc, term, reason string) (int, []string) {
	if strings.TrimSpace(term) == "" {
		return 0, nil
	}

	score := 0
	reasons := make([]string, 0, 4)
	commandWithoutASC := strings.TrimPrefix(doc.Command, "asc ")

	exactCommandMatch := commandWithoutASC == term || doc.Command == term
	if exactCommandMatch {
		return 120, []string{reason, "command:" + term}
	}
	if pathScore := commandPathScore(doc, term); pathScore > 0 {
		score += pathScore
		reasons = append(reasons, reason, "command:"+term)
	}
	if tokenContains(doc.SummaryTokens, term) {
		score += 35
		reasons = append(reasons, reason, "summary:"+term)
	}
	if tokenContains(doc.UsageTokens, term) {
		score += 25
		reasons = append(reasons, reason, "usage:"+term)
	}
	if tokenContains(doc.FlagTokens, term) {
		score += 20
		reasons = append(reasons, reason, "flag:"+term)
	}
	if tokenContains(doc.ExampleTokens, term) {
		score += 18
		reasons = append(reasons, reason, "example:"+term)
	}
	if tokenContains(doc.HelpTokens, term) {
		score += 10
		reasons = append(reasons, reason, "help:"+term)
	}

	if score == 0 && len(term) >= 4 && !strings.Contains(term, "-") {
		for _, suggestion := range suggest.Commands(term, doc.AllTokens) {
			if tokenContains(doc.AllTokens, suggestion) {
				score += 8
				reasons = append(reasons, reason, "fuzzy:"+suggestion)
				break
			}
		}
	}

	return score, uniqueStrings(reasons)
}

func commandPathScore(doc commandDoc, term string) int {
	if exactTokenContains(doc.PathTokens, term) {
		return exactPathTokenScore
	}
	if tokenContains(doc.PathTokens, term) {
		return compoundPathTokenScore
	}
	return 0
}

func exactLeafQueryToken(command string, queryTokens []string) (string, bool) {
	commandParts := strings.Fields(strings.TrimPrefix(command, "asc "))
	if len(commandParts) == 0 {
		return "", false
	}
	leafForms := searchTokenForms(commandParts[len(commandParts)-1])
	for _, token := range queryTokens {
		if searchTokenFormsOverlap(leafForms, searchTokenForms(token)) {
			return token, true
		}
	}
	return "", false
}

func hasSupportingQueryToken(doc commandDoc, queryTokens []string, leafToken string) bool {
	for _, token := range queryTokens {
		if sameSearchStem(token, leafToken) {
			continue
		}
		if tokenContains(doc.PathTokens, token) ||
			tokenContains(doc.SummaryTokens, token) ||
			tokenContains(doc.UsageTokens, token) {
			return true
		}
	}
	return false
}

func canonicalBoostFor(command string, queryTokens []string) (int, string) {
	if target, reason, ok := scopedCanonicalIntent(queryTokens); ok {
		if command == target {
			return canonicalIntentBoost, reason
		}
		return 0, ""
	}

	if releaseDashboardIntent(queryTokens) {
		if command == "asc status" {
			return canonicalIntentBoost, "canonical:release-status"
		}
		return 0, ""
	}

	if statusQueryIntent(queryTokens) && !mutationQueryIntent(queryTokens) {
		if command == "asc versions phased-release view" &&
			tokenContains(queryTokens, "phased") && tokenContains(queryTokens, "release") {
			return canonicalIntentBoost, "canonical:phased-release-status"
		}
		if command == "asc builds beta-app-review-submission view" &&
			tokenContains(queryTokens, "beta") && tokenContains(queryTokens, "review") {
			return canonicalIntentBoost, "canonical:beta-review-status"
		}
	}

	if tokenContains(queryTokens, "upload") && tokenContains(queryTokens, "build") {
		return 0, ""
	}

	for _, rule := range canonicalIntentRules {
		if command != rule.command {
			continue
		}
		if tokenContainsAny(queryTokens, rule.actions) && tokenContainsAny(queryTokens, rule.subjects) {
			return canonicalIntentBoost, rule.reason
		}
	}
	return 0, ""
}

func scopedCanonicalIntent(queryTokens []string) (string, string, bool) {
	if tokenContains(queryTokens, "review") && tokenContains(queryTokens, "attachment") {
		if tokenContainsAny(queryTokens, []string{"delete", "remove"}) {
			return "asc review attachments-delete", "canonical:review-attachment-delete", true
		}
		if tokenContains(queryTokens, "list") {
			return "asc review attachments-list", "canonical:review-attachment-list", true
		}
		if tokenContains(queryTokens, "get") {
			return "asc review attachments-get", "canonical:review-attachment-get", true
		}
		if tokenContains(queryTokens, "upload") {
			return "asc review attachments-upload", "canonical:review-attachment-upload", true
		}
	}
	if tokenContains(queryTokens, "telemetry") {
		if tokenContains(queryTokens, "reset-id") {
			return "asc telemetry reset-id", "canonical:telemetry-reset-id", true
		}
		if tokenContains(queryTokens, "disable") {
			return "asc telemetry disable", "canonical:telemetry-disable", true
		}
		if tokenContains(queryTokens, "enable") {
			return "asc telemetry enable", "canonical:telemetry-enable", true
		}
	}
	if target, reason, ok := scopedAuthActionIntent(queryTokens); ok {
		return target, reason, true
	}
	if !statusQueryIntent(queryTokens) || mutationQueryIntent(queryTokens) {
		return "", "", false
	}
	if tokenContains(queryTokens, "telemetry") {
		return "asc telemetry status", "canonical:telemetry-status", true
	}
	if tokenContains(queryTokens, "auth") {
		if tokenContains(queryTokens, "storekit") {
			return "asc storekit auth status", "canonical:storekit-auth-status", true
		}
		if tokenContains(queryTokens, "ads") {
			return "asc ads auth status", "canonical:ads-auth-status", true
		}
		if tokenContains(queryTokens, "web") {
			return "asc web auth status", "canonical:web-auth-status", true
		}
		return "asc auth status", "canonical:auth-status", true
	}
	if tokenContains(queryTokens, "account") {
		return "asc account status", "canonical:account-status", true
	}
	if tokenContains(queryTokens, "agreement") {
		return "asc web agreements status", "canonical:agreement-status", true
	}
	if tokenContains(queryTokens, "system") {
		return "asc system-status", "canonical:system-status", true
	}
	if tokenContains(queryTokens, "xcode") && tokenContains(queryTokens, "cloud") {
		return "asc xcode-cloud status", "canonical:xcode-cloud-status", true
	}
	if tokenContains(queryTokens, "app") && tokenContains(queryTokens, "clip") && tokenContains(queryTokens, "domain") {
		if tokenContains(queryTokens, "cache") {
			return "asc app-clips domain-status cache", "canonical:app-clip-domain-cache-status", true
		}
		if tokenContains(queryTokens, "debug") {
			return "asc app-clips domain-status debug", "canonical:app-clip-domain-debug-status", true
		}
		return "asc app-clips domain-status", "canonical:app-clip-domain-status", true
	}
	if tokenContainsAny(queryTokens, []string{"testflight", "beta"}) &&
		tokenContains(queryTokens, "review") && tokenContains(queryTokens, "submission") {
		if tokenContains(queryTokens, "list") {
			return "asc testflight review submissions list", "canonical:testflight-review-submissions-list", true
		}
		if tokenContains(queryTokens, "build") {
			return "asc testflight review submissions build", "canonical:testflight-review-submission-build", true
		}
		return "asc testflight review submissions view", "canonical:testflight-review-submission-status", true
	}
	if tokenContains(queryTokens, "testflight") && tokenContains(queryTokens, "review") {
		if !tokenContains(queryTokens, "build") && !explicitReleaseDashboardIntent(queryTokens) {
			return "asc testflight review view", "canonical:testflight-review-status", true
		}
	}
	return "", "", false
}

func scopedAuthActionIntent(queryTokens []string) (string, string, bool) {
	if !tokenContains(queryTokens, "auth") {
		return "", "", false
	}

	for _, scope := range authActionScopes {
		if scope.queryToken != "" && !tokenContains(queryTokens, scope.queryToken) {
			continue
		}
		for _, action := range scope.actions {
			if !tokenContains(queryTokens, action) {
				continue
			}
			leaf := action
			if action == "export" {
				leaf = "export-to-config"
			}
			return scope.commandPrefix + " " + leaf, scope.reasonPrefix + "-" + leaf, true
		}
		return "", "", false
	}

	return "", "", false
}

func releaseDashboardIntent(queryTokens []string) bool {
	if !statusQueryIntent(queryTokens) || unambiguousMutationQueryIntent(queryTokens) {
		return false
	}

	hasTestFlightContext := tokenContainsAny(queryTokens, []string{"testflight", "beta"})
	hasAppStoreContext := tokenContainsAny(queryTokens, []string{"appstore", "store"}) ||
		(tokenContains(queryTokens, "app") && tokenContainsAny(queryTokens, []string{"review", "submission"}))
	hasCrossSurfaceContext := hasTestFlightContext && hasAppStoreContext
	hasExplicitDashboardContext := explicitReleaseDashboardIntent(queryTokens)
	hasScopedReleaseContext := tokenContains(queryTokens, "phased") ||
		(tokenContains(queryTokens, "beta") && tokenContains(queryTokens, "review"))
	if hasScopedReleaseContext && (!hasExplicitDashboardContext || !hasCrossSurfaceContext) {
		return false
	}
	if hasExplicitDashboardContext {
		return true
	}
	return hasCrossSurfaceContext
}

func explicitReleaseDashboardIntent(queryTokens []string) bool {
	hasTestFlightContext := tokenContainsAny(queryTokens, []string{"testflight", "beta"})
	hasAppStoreContext := tokenContainsAny(queryTokens, []string{"appstore", "store"}) ||
		(tokenContains(queryTokens, "app") && tokenContainsAny(queryTokens, []string{"review", "submission"}))
	return tokenContainsAny(queryTokens, []string{"pipeline", "dashboard", "overview"}) &&
		(tokenContains(queryTokens, "release") || (hasTestFlightContext && hasAppStoreContext))
}

func statusQueryIntent(queryTokens []string) bool {
	return tokenContainsAny(queryTokens, []string{"check", "verify", "monitor", "watch", "status", "pipeline", "dashboard", "overview"})
}

func mutationQueryIntent(queryTokens []string) bool {
	return tokenContains(queryTokens, "upload") || unambiguousMutationQueryIntent(queryTokens)
}

func unambiguousMutationQueryIntent(queryTokens []string) bool {
	return tokenContainsAny(queryTokens, []string{
		"create", "update", "edit", "delete", "remove", "set", "pause", "resume",
		"start", "stop", "complete", "submit", "publish", "distribute", "enable", "disable",
	})
}

func tokenContainsAny(tokens, terms []string) bool {
	for _, term := range terms {
		if tokenContains(tokens, term) {
			return true
		}
	}
	return false
}

func aliasesFor(token string) []string {
	switch token {
	case "ship", "shipping":
		return []string{"publish", "submit", "release"}
	case "submission", "submissions":
		return []string{"submit", "review", "appstore"}
	case "review":
		return []string{"submit", "submission", "appstore"}
	case "beta":
		return []string{"testflight"}
	case "tester", "testers", "user", "users":
		return []string{"tester", "testers", "beta-testers", "testflight"}
	case "external":
		return []string{"testflight", "beta", "tester", "testers", "group", "groups"}
	case "cert", "certs":
		return []string{"certificate", "certificates"}
	case "provisioning":
		return []string{"profiles", "profile"}
	case "ipa", "binary":
		return []string{"build", "upload", "uploads"}
	case "appstore", "store":
		return []string{"appstore", "app", "review", "publish"}
	default:
		return nil
	}
}

func commandFlags(cmd *ffcli.Command) []string {
	if cmd.FlagSet == nil {
		return nil
	}
	flags := make([]string, 0)
	cmd.FlagSet.VisitAll(func(f *flag.Flag) {
		if f == nil {
			return
		}
		flags = append(flags, f.Name)
		if strings.TrimSpace(f.Usage) != "" {
			flags = append(flags, f.Usage)
		}
	})
	return flags
}

func extractExamples(longHelp string) []string {
	lines := strings.Split(longHelp, "\n")
	examples := make([]string, 0)
	inExamples := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.EqualFold(trimmed, "Examples:") {
			inExamples = true
			continue
		}
		if !inExamples {
			continue
		}
		if trimmed == "" {
			if len(examples) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, "asc ") {
			examples = append(examples, trimmed)
		}
	}
	return examples
}

func hiddenCommand(cmd *ffcli.Command) bool {
	shortHelp := strings.TrimSpace(cmd.ShortHelp)
	return strings.HasPrefix(shortHelp, "DEPRECATED:") ||
		strings.HasPrefix(shortHelp, "REMOVED:") ||
		strings.HasPrefix(shortHelp, "Compatibility alias:")
}

func searchRows(results []SearchResult) [][]string {
	rows := make([][]string, 0, len(results))
	for _, result := range results {
		rows = append(rows, []string{
			fmt.Sprintf("%d", result.Score),
			result.Command,
			result.Summary,
			summarizeMatches(result.Matched),
		})
	}
	return rows
}

func summarizeMatches(matches []string) string {
	const maxMatches = 6
	if len(matches) <= maxMatches {
		return strings.Join(matches, ", ")
	}
	return strings.Join(matches[:maxMatches], ", ") + fmt.Sprintf(", +%d more", len(matches)-maxMatches)
}

func normalizeQuery(query string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(query)), " ")
}

func uniqueTokens(text string) []string {
	matches := tokenPattern.FindAllString(strings.ToLower(text), -1)
	return uniqueStrings(matches)
}

func tokenContains(tokens []string, term string) bool {
	for _, token := range tokens {
		if searchTokensMatch(token, term) {
			return true
		}
	}
	return false
}

func exactTokenContains(tokens []string, term string) bool {
	termForms := searchTokenForms(strings.ToLower(strings.TrimSpace(term)))
	for _, token := range tokens {
		if searchTokenFormsOverlap(searchTokenForms(strings.ToLower(strings.TrimSpace(token))), termForms) {
			return true
		}
	}
	return false
}

func searchTokensMatch(token, term string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	term = strings.ToLower(strings.TrimSpace(term))
	if token == "" || term == "" {
		return false
	}
	if token == term {
		return true
	}

	termForms := searchTokenForms(term)
	tokenParts := strings.Split(token, "-")
	for _, tokenPart := range tokenParts {
		if searchTokenFormsOverlap(searchTokenForms(tokenPart), termForms) {
			return true
		}
	}
	return false
}

func sameSearchStem(left, right string) bool {
	left = strings.ToLower(strings.TrimSpace(left))
	right = strings.ToLower(strings.TrimSpace(right))
	return left != "" && right != "" && searchTokenFormsOverlap(searchTokenForms(left), searchTokenForms(right))
}

func searchTokenForms(token string) []string {
	forms := []string{token}
	if len(token) > 4 && strings.HasSuffix(token, "ies") {
		forms = append(forms, strings.TrimSuffix(token, "ies")+"y")
		return uniqueStrings(forms)
	}
	if len(token) > 3 && strings.HasSuffix(token, "es") {
		forms = append(forms, strings.TrimSuffix(token, "es"))
	}
	if len(token) > 3 && strings.HasSuffix(token, "s") &&
		!strings.HasSuffix(token, "ss") &&
		!strings.HasSuffix(token, "us") &&
		!strings.HasSuffix(token, "is") {
		forms = append(forms, strings.TrimSuffix(token, "s"))
	}
	return uniqueStrings(forms)
}

func searchTokenFormsOverlap(left, right []string) bool {
	for _, leftForm := range left {
		for _, rightForm := range right {
			if leftForm == rightForm {
				return true
			}
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func addReason(reasons *[]string, seen map[string]struct{}, reason string) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return
	}
	if _, ok := seen[reason]; ok {
		return
	}
	seen[reason] = struct{}{}
	*reasons = append(*reasons, reason)
}
