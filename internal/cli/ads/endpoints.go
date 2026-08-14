package ads

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleads"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

type endpointFlagValues struct {
	common  commonFlags
	output  shared.OutputFlags
	flagSet *flag.FlagSet

	file     *string
	confirm  *bool
	paginate *bool

	pathStrings   map[string]*string
	queryStrings  map[string]*string
	queryRepeated map[string]*repeatedFlagValue
	queryInts     map[string]*int
	queryBools    map[string]*bool
}

// repeatedFlagValue preserves each occurrence of a repeated CLI flag. A
// single occurrence may still contain comma-separated values for compatibility
// with the API's existing examples.
type repeatedFlagValue struct {
	values []string
}

func (v *repeatedFlagValue) String() string {
	if v == nil {
		return ""
	}
	return strings.Join(v.values, ",")
}

func (v *repeatedFlagValue) Set(value string) error {
	v.values = append(v.values, value)
	return nil
}

type commandNode struct {
	name     string
	children map[string]*commandNode
	spec     *appleads.EndpointSpec
}

func endpointCommands() []*ffcli.Command {
	return commandsForEndpointSpecs(appleads.EndpointSpecs(), nil)
}

func platformEndpointCommands() []*ffcli.Command {
	return commandsForEndpointSpecs(appleads.PlatformEndpointSpecs(), []string{"platform"})
}

func commandsForEndpointSpecs(specs []appleads.EndpointSpec, commandPrefix []string) []*ffcli.Command {
	root := &commandNode{children: map[string]*commandNode{}}
	for _, spec := range specs {
		addSpec(root, spec)
	}
	commands := make([]*ffcli.Command, 0, len(root.children))
	for _, name := range sortedChildNames(root) {
		commands = append(commands, buildNodeCommand(root.children[name], nil, commandPrefix))
	}
	return commands
}

func addSpec(root *commandNode, spec appleads.EndpointSpec) {
	current := root
	for index, part := range spec.CommandPath {
		if current.children == nil {
			current.children = map[string]*commandNode{}
		}
		child := current.children[part]
		if child == nil {
			child = &commandNode{name: part, children: map[string]*commandNode{}}
			current.children[part] = child
		}
		current = child
		if spec.DefaultListAlias && index == 0 {
			specCopy := spec
			current.spec = &specCopy
		}
	}
	specCopy := spec
	current.spec = &specCopy
}

func buildNodeCommand(node *commandNode, parentPath, commandPrefix []string) *ffcli.Command {
	path := append(append([]string(nil), parentPath...), node.name)
	displayPath := append(append([]string(nil), commandPrefix...), path...)
	var flags endpointFlagValues
	var fs *flag.FlagSet
	if node.spec != nil {
		fs, flags = bindEndpointFlags(*node.spec, strings.Join(path, " "))
	} else {
		fs = flag.NewFlagSet(strings.Join(path, " "), flag.ExitOnError)
	}

	subcommands := []*ffcli.Command{}
	for _, name := range sortedChildNames(node) {
		subcommands = append(subcommands, buildNodeCommand(node.children[name], path, commandPrefix))
	}
	if len(commandPrefix) == 0 && len(path) == 1 && path[0] == "reports" {
		subcommands = append(subcommands, ReportsPresetCommand())
	}
	if len(commandPrefix) == 0 {
		subcommands = append(subcommands, workflowSubcommands(path, &flags)...)
	}
	if slices.Equal(commandPrefix, []string{"platform"}) {
		subcommands = append(subcommands, platformWorkflowSubcommands(path)...)
	}

	command := &ffcli.Command{
		Name:        node.name,
		ShortUsage:  "asc ads " + strings.Join(displayPath, " ") + " [flags]",
		ShortHelp:   endpointShortHelp(node),
		LongHelp:    endpointLongHelp(node, displayPath),
		FlagSet:     fs,
		UsageFunc:   shared.DefaultUsageFunc,
		Subcommands: subcommands,
	}
	if node.spec != nil {
		spec := *node.spec
		command.Exec = func(ctx context.Context, args []string) error {
			if err := rejectUnexpectedArgs(args); err != nil {
				return err
			}
			return executeEndpoint(ctx, spec, flags)
		}
	}
	return command
}

func sortedChildNames(node *commandNode) []string {
	names := make([]string, 0, len(node.children))
	for name := range node.children {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func endpointShortHelp(node *commandNode) string {
	if node.spec == nil {
		return endpointGroupHelp(node.name)
	}
	switch node.spec.Name {
	case "get-me-details", "get-user-acl":
		return sentenceFromEndpointName(node.spec.Name)
	}
	if len(node.children) > 0 {
		return "Manage Apple Ads " + strings.ReplaceAll(node.name, "-", " ") + "."
	}
	return sentenceFromEndpointName(node.spec.Name)
}

func endpointLongHelp(node *commandNode, path []string) string {
	if node.spec == nil {
		return fmt.Sprintf("%s\n\nExamples:\n  asc ads %s --help", endpointGroupHelp(node.name), strings.Join(path, " "))
	}
	examples := []string{"  asc ads " + strings.Join(path, " ")}
	for _, param := range node.spec.PathParams {
		if param.ContextValue {
			continue
		}
		examples[0] += fmt.Sprintf(" --%s %s", param.Flag, strings.ToUpper(param.Flag))
	}
	for _, param := range node.spec.QueryParams {
		if !param.Required {
			continue
		}
		if param.Type == appleads.ParamBool {
			examples[0] += fmt.Sprintf(" --%s", param.Flag)
			continue
		}
		examples[0] += fmt.Sprintf(" --%s %s", param.Flag, strings.ToUpper(strings.ReplaceAll(param.Flag, "-", "_")))
	}
	if node.spec.Name == "platform-search-apps" {
		examples[0] += " --query EXAMPLE"
	}
	if node.spec.BodyKind != appleads.BodyNone {
		if node.spec.BodyOptional {
			examples[0] += " [--file payload.json]"
		} else {
			examples[0] += " --file payload.json"
		}
	}
	switch {
	case node.spec.RequiresConfirm:
		examples[0] += " --confirm"
	case node.spec.ConfirmBodyField != "":
		examples[0] += " [--confirm]"
	}
	if node.spec.RequiresOrg {
		examples[0] += " --org ORG_ID"
	}
	switch node.spec.Context {
	case appleads.ContextAdAccount:
		examples[0] += " --ad-account AD_ACCOUNT_ID"
	case appleads.ContextAdAccountOptional:
		examples[0] += " [--ad-account AD_ACCOUNT_ID]"
	}
	help := fmt.Sprintf("%s\n\nEndpoint: %s %s", endpointShortHelp(node), node.spec.Method, node.spec.Path)
	if node.spec.BodyType == "UpdateCampaignRequest" {
		help += "\n\nPayload:\n  Apple requires a \"campaign\" envelope for campaign updates.\n  Example: {\"campaign\":{\"status\":\"PAUSED\"}}"
	}
	return help + "\n\nExamples:\n" + strings.Join(examples, "\n")
}

func endpointGroupHelp(name string) string {
	switch name {
	case "acls":
		return "List Apple Ads account ACLs."
	case "advertiser-resources":
		return "List Apple Ads advertiser resources."
	case "me":
		return "View the current Apple Ads user."
	case "orgs":
		return "View Apple Ads organizations."
	case "geo":
		return "Manage Apple Ads geographic targeting resources."
	default:
		return "Manage Apple Ads " + strings.ReplaceAll(name, "-", " ") + "."
	}
}

func sentenceFromEndpointName(name string) string {
	switch name {
	case "get-me-details", "platform-get-me-details":
		return "View the current Apple Ads user."
	case "get-user-acl", "platform-get-user-acls":
		return "List Apple Ads account ACLs."
	}
	text := strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(name), "platform-"), "-", " ")
	replacements := []struct {
		old string
		new string
	}{
		{"get all ", "List all "},
		{"get a ", "View a "},
		{"get an ", "View an "},
		{"get ", "View "},
		{"gets a ", "View a "},
		{"search for ", "Search for "},
		{"search ", "Search "},
		{"query ", "Find "},
		{"find ", "Find "},
		{"create a ", "Create a "},
		{"create an ", "Create an "},
		{"create ", "Create "},
		{"update a ", "Update a "},
		{"update an ", "Update an "},
		{"update ", "Update "},
		{"delete a ", "Delete a "},
		{"delete an ", "Delete an "},
		{"delete ", "Delete "},
		{"impression share report", "Create impression share report"},
	}
	for _, replacement := range replacements {
		if strings.HasPrefix(text, replacement.old) {
			text = replacement.new + strings.TrimPrefix(text, replacement.old)
			break
		}
	}
	if text == "" {
		text = name
	}
	return strings.TrimSuffix(text, ".") + "."
}

func bindEndpointFlags(spec appleads.EndpointSpec, flagSetName string) (*flag.FlagSet, endpointFlagValues) {
	fs := flag.NewFlagSet(flagSetName, flag.ExitOnError)
	values := endpointFlagValues{
		common: commonFlags{
			AdsProfile: fs.String("ads-profile", "", "Use named Apple Ads authentication profile"),
		},
		output:        shared.BindOutputFlags(fs),
		flagSet:       fs,
		pathStrings:   map[string]*string{},
		queryStrings:  map[string]*string{},
		queryRepeated: map[string]*repeatedFlagValue{},
		queryInts:     map[string]*int{},
		queryBools:    map[string]*bool{},
	}
	if spec.RequiresOrg {
		values.common.Org = fs.String("org", "", "Apple Ads organization ID (or ASC_ADS_ORG_ID env)")
	}
	if spec.Context == appleads.ContextAdAccount || spec.Context == appleads.ContextAdAccountOptional {
		values.common.AdAccount = fs.String("ad-account", "", "Apple Ads ad account ID (or ASC_ADS_AD_ACCOUNT_ID env)")
	}
	for _, param := range spec.PathParams {
		if param.ContextValue {
			continue
		}
		values.pathStrings[param.Name] = fs.String(param.Flag, "", flagUsage(param))
	}
	for _, param := range spec.QueryParams {
		switch param.Type {
		case appleads.ParamInt:
			values.queryInts[param.Name] = fs.Int(param.Flag, 0, flagUsage(param))
		case appleads.ParamBool:
			values.queryBools[param.Name] = fs.Bool(param.Flag, false, flagUsage(param))
		default:
			if param.Repeated {
				repeated := &repeatedFlagValue{}
				values.queryRepeated[param.Name] = repeated
				fs.Var(repeated, param.Flag, flagUsage(param))
				continue
			}
			values.queryStrings[param.Name] = fs.String(param.Flag, "", flagUsage(param))
		}
	}
	if spec.BodyKind != appleads.BodyNone {
		values.file = fs.String("file", "", "Path to Apple Ads JSON payload")
	}
	if spec.RequiresConfirm {
		values.confirm = fs.Bool("confirm", false, "Confirm this destructive Apple Ads operation")
	}
	if spec.ConfirmBodyField != "" && values.confirm == nil {
		values.confirm = fs.Bool("confirm", false, "Confirm an Apple Ads update that replaces delegations")
	}
	if spec.SupportsPaginate {
		values.paginate = fs.Bool("paginate", false, "Automatically fetch all pages (aggregate results)")
	}
	return fs, values
}

func flagUsage(param appleads.ParamSpec) string {
	usage := strings.ReplaceAll(param.Flag, "-", " ")
	if param.Required {
		usage += " (required)"
	}
	if param.Max > 0 {
		usage += fmt.Sprintf(" (max %d)", param.Max)
	}
	if len(param.Allowed) > 0 {
		usage += " (" + strings.Join(param.Allowed, ", ") + ")"
	}
	return usage
}

func executeEndpoint(ctx context.Context, spec appleads.EndpointSpec, flags endpointFlagValues) error {
	if spec.RequiresConfirm && flags.confirm != nil && !*flags.confirm {
		return shared.UsageError("--confirm is required")
	}
	pathParams, err := collectPathParams(spec, flags)
	if err != nil {
		return shared.UsageError(err.Error())
	}
	query, err := collectQuery(spec, flags)
	if err != nil {
		return shared.UsageError(err.Error())
	}
	body, err := readBody(spec, flags)
	if err != nil {
		return err
	}
	if err := validateEndpointBody(spec, body, flags.confirm != nil && *flags.confirm); err != nil {
		return shared.UsageError(err.Error())
	}

	var client *appleads.Client
	if spec.Version == appleads.APIVersionPlatformV1 {
		var adAccountID string
		client, adAccountID, err = resolvePlatformClientAndAdAccountID(ctx, flags.common, spec.Context)
		if err != nil {
			return fmt.Errorf("ads: %w", err)
		}
		for _, param := range spec.PathParams {
			if param.ContextValue {
				pathParams[param.Name] = adAccountID
			}
		}
	}
	if spec.Version != appleads.APIVersionPlatformV1 {
		client, err = resolveClient(ctx, flags.common, spec.RequiresOrg)
	}
	if err != nil {
		return fmt.Errorf("ads: %w", err)
	}

	requestCtx, cancel := requestContext(ctx)
	defer cancel()

	var result appleads.RawResponse
	if flags.paginate != nil && *flags.paginate {
		startOffset := intValue(flags.queryInts["offset"])
		pageSize := intValue(flags.queryInts["limit"])
		if pageSize == 0 {
			// Geo search uses the Platform API's pageSize spelling instead of
			// the limit used by apps and the legacy API.
			pageSize = intValue(flags.queryInts["pageSize"])
		}
		result, err = client.PaginateAll(requestCtx, spec, pathParams, query, startOffset, pageSize, body)
	} else {
		result, err = client.Do(requestCtx, spec, pathParams, query, body)
	}
	if err != nil {
		return fmt.Errorf("ads %s: %w", strings.Join(spec.CommandPath, " "), err)
	}
	return shared.PrintOutput(result, *flags.output.Output, *flags.output.Pretty)
}

func collectPathParams(spec appleads.EndpointSpec, flags endpointFlagValues) (map[string]string, error) {
	params := map[string]string{}
	for _, param := range spec.PathParams {
		if param.ContextValue {
			continue
		}
		ptr := flags.pathStrings[param.Name]
		value := value(ptr)
		if param.Required && value == "" {
			return nil, fmt.Errorf("--%s is required", param.Flag)
		}
		if value != "" && param.Type == appleads.ParamInt {
			if parsed, err := strconv.ParseInt(value, 10, 64); err != nil {
				return nil, fmt.Errorf("--%s must be an integer", param.Flag)
			} else if parsed < 0 {
				return nil, fmt.Errorf("--%s must be >= 0", param.Flag)
			}
		}
		params[param.Name] = value
	}
	return params, nil
}

func collectQuery(spec appleads.EndpointSpec, flags endpointFlagValues) (url.Values, error) {
	query := url.Values{}
	for _, param := range spec.QueryParams {
		switch param.Type {
		case appleads.ParamInt:
			raw := intValue(flags.queryInts[param.Name])
			provided := flagProvided(flags.flagSet, param.Flag)
			if raw == 0 {
				if param.Required {
					return nil, fmt.Errorf("--%s is required", param.Flag)
				}
				if provided && (param.Name == "limit" || param.Name == "pageSize") {
					maxLimit := appleads.MaxPageLimit(spec)
					if maxLimit > 0 {
						return nil, fmt.Errorf("--%s must be between 1 and %d", param.Flag, maxLimit)
					}
					return nil, fmt.Errorf("--%s must be greater than 0", param.Flag)
				}
				continue
			}
			if raw < 0 {
				return nil, fmt.Errorf("--%s must be >= 0", param.Flag)
			}
			if param.Max > 0 && param.Name != "limit" && raw > param.Max {
				return nil, fmt.Errorf("--%s must be at most %d", param.Flag, param.Max)
			}
			if param.Name == "limit" {
				maxLimit := appleads.MaxPageLimit(spec)
				if raw < 1 || (maxLimit > 0 && raw > maxLimit) {
					if maxLimit == 0 {
						return nil, fmt.Errorf("--limit must be greater than 0")
					}
					return nil, fmt.Errorf("--limit must be between 1 and %d", maxLimit)
				}
			}
			query.Set(param.Name, strconv.Itoa(raw))
		case appleads.ParamBool:
			if ptr := flags.queryBools[param.Name]; ptr != nil && *ptr {
				query.Set(param.Name, "true")
			}
		default:
			raw := value(flags.queryStrings[param.Name])
			if spec.Name == "platform-search-geo-locations" && (param.Name == "supplySource" || param.Name == "countrycode") {
				raw = strings.ToUpper(raw)
			}
			if param.Repeated {
				rawValues := []string(nil)
				if repeated := flags.queryRepeated[param.Name]; repeated != nil {
					rawValues = repeated.values
				} else if raw != "" {
					rawValues = []string{raw}
				}
				if len(rawValues) == 0 {
					if param.Required {
						return nil, fmt.Errorf("--%s is required", param.Flag)
					}
					continue
				}
				for _, occurrence := range rawValues {
					for _, part := range strings.Split(occurrence, ",") {
						part = strings.TrimSpace(part)
						if part == "" {
							return nil, fmt.Errorf("--%s must not contain empty values", param.Flag)
						}
						if err := validateAllowed(param, part); err != nil {
							return nil, err
						}
						if param.Name == "storeFronts" {
							if len(part) != 2 || !isASCIIAlpha(part[0]) || !isASCIIAlpha(part[1]) {
								return nil, fmt.Errorf("--%s values must be ISO 3166-1 alpha-2 country or region codes", param.Flag)
							}
							part = strings.ToUpper(part)
						}
						query.Add(param.Name, part)
					}
				}
				continue
			}
			if raw == "" {
				if param.Required {
					return nil, fmt.Errorf("--%s is required", param.Flag)
				}
				continue
			}
			if err := validateAllowed(param, raw); err != nil {
				return nil, err
			}
			query.Set(param.Name, raw)
		}
	}
	if spec.Name == "platform-search-apps" {
		if err := validatePlatformAppSearch(query); err != nil {
			return nil, err
		}
	}
	if spec.Name == "platform-search-geo-locations" {
		if err := validatePlatformGeoSearch(query); err != nil {
			return nil, err
		}
	}
	return query, nil
}

func isASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func validatePlatformAppSearch(query url.Values) error {
	text := strings.TrimSpace(query.Get("query"))
	if text == "" && strings.TrimSpace(query.Get("cpids")) == "" && query.Get("returnOwnedApps") != "true" {
		return fmt.Errorf("at least one of --query, --cpids, or --return-owned-apps is required")
	}
	if text == "" {
		return nil
	}
	if !strings.ContainsFunc(text, unicode.IsLetter) && !strings.ContainsFunc(text, unicode.IsDigit) {
		return fmt.Errorf("--query must contain at least one alphanumeric character")
	}
	minimum := 3
	if strings.ContainsFunc(text, func(r rune) bool {
		return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul)
	}) {
		minimum = 2
	}
	if utf8.RuneCountInString(text) < minimum {
		return fmt.Errorf("--query must contain at least %d characters", minimum)
	}
	return nil
}

func validatePlatformGeoSearch(query url.Values) error {
	text := strings.TrimSpace(query.Get("query"))
	if text != "" && text != "*" && utf8.RuneCountInString(text) < 2 {
		return fmt.Errorf("--query must contain at least 2 characters")
	}
	countryCode := query.Get("countrycode")
	if countryCode != "" && (len(countryCode) != 2 || !isASCIIAlpha(countryCode[0]) || !isASCIIAlpha(countryCode[1])) {
		return fmt.Errorf("--country-code must be an ISO 3166-1 alpha-2 country or region code")
	}
	return nil
}

func flagProvided(fs *flag.FlagSet, name string) bool {
	if fs == nil {
		return false
	}
	provided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

func validateAllowed(param appleads.ParamSpec, raw string) error {
	if len(param.Allowed) == 0 {
		return nil
	}
	allowed := map[string]struct{}{}
	for _, item := range param.Allowed {
		allowed[item] = struct{}{}
	}
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if _, ok := allowed[value]; !ok {
			return fmt.Errorf("--%s must be one of: %s", param.Flag, strings.Join(param.Allowed, ", "))
		}
	}
	return nil
}

func readBody(spec appleads.EndpointSpec, flags endpointFlagValues) (json.RawMessage, error) {
	if spec.BodyKind == appleads.BodyNone {
		return nil, nil
	}
	fileValue := value(flags.file)
	if fileValue == "" {
		if spec.BodyOptional {
			return nil, nil
		}
		fmt.Fprintln(os.Stderr, "Error: --file is required")
		return nil, shared.MissingRequiredUsageError()
	}
	kind := shared.JSONPayloadObject
	if spec.BodyKind == appleads.BodyArray {
		kind = shared.JSONPayloadArray
	}
	payload, err := shared.ReadJSONFilePayloadKind(fileValue, kind)
	if err != nil {
		return nil, fmt.Errorf("ads %s: %w", strings.Join(spec.CommandPath, " "), err)
	}
	return payload, nil
}

func validateEndpointBody(spec appleads.EndpointSpec, body json.RawMessage, confirmed bool) error {
	if len(body) == 0 || spec.Version != appleads.APIVersionPlatformV1 {
		return nil
	}
	if spec.Name != "platform-create-ad-account" && spec.Name != "platform-update-ad-account" {
		return nil
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("invalid JSON object: %w", err)
	}
	if spec.Name == "platform-create-ad-account" {
		if err := requireNonEmptyJSONString(payload, "name"); err != nil {
			return err
		}
		features, ok := payload["productFeatures"]
		if !ok {
			return fmt.Errorf("productFeatures is required")
		}
		if err := validateProductFeatures(features); err != nil {
			return err
		}
	}
	if spec.Name == "platform-update-ad-account" {
		if _, present := payload["productFeatures"]; present {
			return fmt.Errorf("productFeatures is immutable and is not supported by ad-account update")
		}
		if rawName, present := payload["name"]; present {
			var name string
			if err := json.Unmarshal(rawName, &name); err != nil || strings.TrimSpace(name) == "" {
				return fmt.Errorf("name must be a non-empty string")
			}
		}
	}
	if delegations, present := payload["delegations"]; present {
		if spec.ConfirmBodyField == "delegations" && !confirmed {
			return fmt.Errorf("--confirm is required when replacing delegations")
		}
		if err := validateDelegations(delegations); err != nil {
			return err
		}
	}
	return nil
}

func requireNonEmptyJSONString(payload map[string]json.RawMessage, field string) error {
	raw, ok := payload[field]
	if !ok {
		return fmt.Errorf("%s is required", field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must be a non-empty string", field)
	}
	return nil
}

func validateProductFeatures(raw json.RawMessage) error {
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || len(values) != 1 {
		return fmt.Errorf("productFeatures must contain exactly one value")
	}
	for _, value := range values {
		if value != "APPSTORE_APP_MANUAL" && value != "BUSINESS_BRAND_MANUAL" {
			return fmt.Errorf("productFeatures values must be APPSTORE_APP_MANUAL or BUSINESS_BRAND_MANUAL")
		}
	}
	return nil
}

func validateDelegations(raw json.RawMessage) error {
	var values []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("delegations must be an array")
	}
	for index, delegation := range values {
		if err := requireNonEmptyJSONString(delegation, "resourceId"); err != nil {
			return fmt.Errorf("delegations[%d]: %w", index, err)
		}
		rawType, ok := delegation["resourceType"]
		if !ok {
			return fmt.Errorf("delegations[%d].resourceType is required", index)
		}
		var resourceType string
		if err := json.Unmarshal(rawType, &resourceType); err != nil || (resourceType != "CONTENT_PROVIDER" && resourceType != "BUSINESS_BRAND") {
			return fmt.Errorf("delegations[%d].resourceType must be CONTENT_PROVIDER or BUSINESS_BRAND", index)
		}
	}
	return nil
}

func intValue(ptr *int) int {
	if ptr == nil {
		return 0
	}
	return *ptr
}
