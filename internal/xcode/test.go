package xcode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TestAction identifies the xcodebuild operation selected by TestOptions.
type TestAction string

const (
	TestActionTest                TestAction = "test"
	TestActionBuildForTesting     TestAction = "build-for-testing"
	TestActionTestWithoutBuilding TestAction = "test-without-building"
	maxTestFailureMessage                    = 4096
	maxTestFailureCount                      = 100
	maxTestCaseCount                         = 10000
)

// TestOptions describes a local xcodebuild test operation.
type TestOptions struct {
	WorkspacePath    string
	ProjectPath      string
	Scheme           string
	Action           string
	Configuration    string
	Destinations     []string
	TestPlan         string
	XctestrunPath    string
	OnlyTesting      []string
	SkipTesting      []string
	DerivedDataPath  string
	ResultBundlePath string
	Clean            bool
	NoCodeSigning    bool
	XcodebuildArgs   []string
	LogWriter        io.Writer
}

// TestResult is the stable structured result for a local Xcode test operation.
type TestResult struct {
	WorkspacePath    string       `json:"workspace,omitempty"`
	ProjectPath      string       `json:"project,omitempty"`
	Scheme           string       `json:"scheme,omitempty"`
	Action           string       `json:"action"`
	Configuration    string       `json:"configuration,omitempty"`
	Destinations     []string     `json:"destinations,omitempty"`
	TestPlan         string       `json:"test_plan,omitempty"`
	XctestrunPath    string       `json:"xctestrun_path,omitempty"`
	DerivedDataPath  string       `json:"derived_data_path,omitempty"`
	ResultBundlePath string       `json:"result_bundle_path,omitempty"`
	Tests            *TestSummary `json:"tests,omitempty"`
	Clean            bool         `json:"clean"`
	NoCodeSigning    bool         `json:"no_code_signing"`
	Success          bool         `json:"success"`
	DurationMS       int64        `json:"duration_ms"`
	ExitStatus       *int         `json:"exit_status,omitempty"`
}

// TestSummary contains the structured counts extracted from an xcresult.
type TestSummary struct {
	Total      int           `json:"total"`
	Passed     int           `json:"passed"`
	Failed     int           `json:"failed"`
	Skipped    int           `json:"skipped"`
	DurationMS int64         `json:"duration_ms"`
	Cases      []TestCase    `json:"cases,omitempty"`
	Failures   []TestFailure `json:"failures,omitempty"`
}

// TestCase is a bounded structured representation of one test case.
type TestCase struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name,omitempty"`
	Classname  string `json:"classname,omitempty"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Message    string `json:"message,omitempty"`
}

// TestFailure describes a failed test without including its complete log.
type TestFailure struct {
	Identifier string `json:"identifier"`
	Message    string `json:"message,omitempty"`
}

var (
	runXcodeTestCommand     = runXcodebuildForBuild
	readTestResultSummaryFn = readTestResultSummary
	testNowFn               = time.Now
)

// ValidateTestOptions checks deterministic command-shape errors without
// reading the filesystem or starting a subprocess.
func ValidateTestOptions(opts TestOptions) error {
	opts = normalizeTestOptions(opts)
	if opts.Action == "" {
		opts.Action = string(TestActionTest)
	}
	switch TestAction(opts.Action) {
	case TestActionTest, TestActionBuildForTesting:
		if err := validateWorkspaceProjectPair(opts.WorkspacePath, opts.ProjectPath); err != nil {
			return err
		}
		if opts.Scheme == "" {
			return fmt.Errorf("--scheme is required")
		}
		if opts.ProjectPath != "" && !strings.EqualFold(filepath.Ext(opts.ProjectPath), ".xcodeproj") {
			return fmt.Errorf("--project must end with .xcodeproj")
		}
		if opts.WorkspacePath != "" && !strings.EqualFold(filepath.Ext(opts.WorkspacePath), ".xcworkspace") {
			return fmt.Errorf("--workspace must end with .xcworkspace")
		}
		if opts.XctestrunPath != "" {
			return fmt.Errorf("--xctestrun is only valid with --action test-without-building")
		}
	case TestActionTestWithoutBuilding:
		if opts.ProjectPath != "" || opts.WorkspacePath != "" {
			return fmt.Errorf("--project and --workspace cannot be used with --action test-without-building")
		}
		if opts.Scheme != "" {
			return fmt.Errorf("--scheme cannot be used with --action test-without-building")
		}
		if opts.XctestrunPath == "" {
			return fmt.Errorf("--xctestrun is required")
		}
		if !strings.EqualFold(filepath.Ext(opts.XctestrunPath), ".xctestrun") {
			return fmt.Errorf("--xctestrun must end with .xctestrun")
		}
	default:
		return fmt.Errorf("--action must be one of: test, build-for-testing, test-without-building")
	}
	if len(opts.Destinations) == 0 {
		return fmt.Errorf("--destination is required")
	}
	for _, destination := range opts.Destinations {
		if strings.TrimSpace(destination) == "" {
			return fmt.Errorf("--destination cannot be empty")
		}
	}
	if opts.TestPlan != "" && opts.XctestrunPath != "" {
		return fmt.Errorf("--test-plan cannot be used with --xctestrun")
	}
	if opts.Clean && TestAction(opts.Action) == TestActionTestWithoutBuilding {
		return fmt.Errorf("--clean cannot be used with --action test-without-building")
	}
	if opts.NoCodeSigning && TestAction(opts.Action) == TestActionTestWithoutBuilding {
		return fmt.Errorf("--no-code-signing cannot be used with --action test-without-building")
	}
	for _, value := range append(append([]string{}, opts.OnlyTesting...), opts.SkipTesting...) {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("test filter cannot be empty")
		}
	}
	for _, arg := range opts.XcodebuildArgs {
		if strings.TrimSpace(arg) == "" {
			return fmt.Errorf("--xcodebuild-flag cannot be empty")
		}
	}
	if reserved := reservedTestPassthroughArgument(opts.XcodebuildArgs); reserved != "" {
		return fmt.Errorf("--xcodebuild-flag cannot override asc-managed argument %q", reserved)
	}
	if opts.ResultBundlePath != "" && !strings.EqualFold(filepath.Ext(opts.ResultBundlePath), ".xcresult") {
		return fmt.Errorf("--result-bundle-path must end with .xcresult")
	}
	return nil
}

// Test runs a local xcodebuild test operation. For test-executing actions it
// reads the structured result bundle after xcodebuild exits. A subprocess
// failure is preserved even when its partial result bundle can be summarized.
func Test(ctx context.Context, opts TestOptions) (*TestResult, error) {
	startedAt := testNowFn()
	opts = normalizeTestOptions(opts)
	if opts.Action == "" {
		opts.Action = string(TestActionTest)
	}
	result := &TestResult{
		WorkspacePath: opts.WorkspacePath,
		ProjectPath:   opts.ProjectPath,
		Scheme:        opts.Scheme,
		Action:        opts.Action,
		Configuration: opts.Configuration,
		Destinations:  cloneStrings(opts.Destinations),
		TestPlan:      opts.TestPlan,
		XctestrunPath: opts.XctestrunPath,
		Clean:         opts.Clean,
		NoCodeSigning: opts.NoCodeSigning,
	}
	finish := func(err error) (*TestResult, error) {
		result.DurationMS = max(int64(0), testNowFn().Sub(startedAt).Milliseconds())
		result.Success = err == nil
		return result, err
	}

	if err := ValidateTestOptions(opts); err != nil {
		return finish(err)
	}
	if opts.Action != string(TestActionTestWithoutBuilding) {
		derivedDataPath, err := resolveTestDerivedDataPath(opts)
		if err != nil {
			return finish(err)
		}
		opts.DerivedDataPath = derivedDataPath
		result.DerivedDataPath = derivedDataPath
	} else if opts.DerivedDataPath != "" {
		derivedDataPath, err := filepath.Abs(opts.DerivedDataPath)
		if err != nil {
			return finish(fmt.Errorf("resolve derived data path: %w", err))
		}
		opts.DerivedDataPath = filepath.Clean(derivedDataPath)
		result.DerivedDataPath = opts.DerivedDataPath
	}
	if opts.Action != string(TestActionBuildForTesting) {
		resultBundlePath, err := resolveTestResultBundlePath(opts)
		if err != nil {
			return finish(err)
		}
		opts.ResultBundlePath = resultBundlePath
		result.ResultBundlePath = resultBundlePath
	} else if opts.ResultBundlePath != "" {
		resultBundlePath, err := resolveTestResultBundlePath(opts)
		if err != nil {
			return finish(err)
		}
		opts.ResultBundlePath = resultBundlePath
		result.ResultBundlePath = resultBundlePath
	}
	if err := validateTestResultBundleDestination(opts.ResultBundlePath); err != nil {
		return finish(err)
	}
	if err := validateTestInputPaths(opts); err != nil {
		return finish(err)
	}
	if err := ensureXcodeAvailable(ctx); err != nil {
		return finish(err)
	}
	if opts.ResultBundlePath != "" {
		if err := os.MkdirAll(filepath.Dir(opts.ResultBundlePath), 0o755); err != nil {
			return finish(fmt.Errorf("create result bundle parent directory: %w", err))
		}
	}

	command := buildTestCommand(opts)
	processErr := runXcodeTestCommand(ctx, command, opts.LogWriter)
	if processErr != nil {
		setTestExitStatus(result, processErr)
		if opts.Action != string(TestActionBuildForTesting) && existingDirectory(opts.ResultBundlePath) {
			if summary, summaryErr := readTestResultSummaryFn(ctx, opts.ResultBundlePath); summaryErr == nil {
				result.Tests = summary
			}
		}
		return finish(processErr)
	}

	if opts.Action == string(TestActionBuildForTesting) {
		result.XctestrunPath = findXctestrunPath(opts.DerivedDataPath)
		exitStatus := 0
		result.ExitStatus = &exitStatus
		return finish(nil)
	}

	summary, err := readTestResultSummaryFn(ctx, opts.ResultBundlePath)
	if err != nil {
		return finish(fmt.Errorf("read test result summary: %w", err))
	}
	result.Tests = summary
	exitStatus := 0
	result.ExitStatus = &exitStatus
	return finish(nil)
}

func normalizeTestOptions(opts TestOptions) TestOptions {
	opts.WorkspacePath = normalizeDirectoryPath(opts.WorkspacePath)
	opts.ProjectPath = normalizeDirectoryPath(opts.ProjectPath)
	opts.Scheme = strings.TrimSpace(opts.Scheme)
	opts.Action = strings.TrimSpace(opts.Action)
	opts.Configuration = strings.TrimSpace(opts.Configuration)
	opts.Destinations = trimTestValues(opts.Destinations)
	opts.TestPlan = strings.TrimSpace(opts.TestPlan)
	opts.XctestrunPath = normalizeDirectoryPath(opts.XctestrunPath)
	opts.OnlyTesting = trimTestValues(opts.OnlyTesting)
	opts.SkipTesting = trimTestValues(opts.SkipTesting)
	opts.DerivedDataPath = normalizeDirectoryPath(opts.DerivedDataPath)
	opts.ResultBundlePath = normalizeDirectoryPath(opts.ResultBundlePath)
	opts.XcodebuildArgs = trimTestValues(opts.XcodebuildArgs)
	return opts
}

func trimTestValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		trimmed = append(trimmed, strings.TrimSpace(value))
	}
	return trimmed
}

func validateTestInputPaths(opts TestOptions) error {
	if opts.Action == string(TestActionTestWithoutBuilding) {
		return validateExistingFile(opts.XctestrunPath, "--xctestrun")
	}
	if opts.WorkspacePath != "" {
		return validateExistingPath(opts.WorkspacePath, ".xcworkspace", "--workspace")
	}
	return validateExistingPath(opts.ProjectPath, ".xcodeproj", "--project")
}

func resolveTestDerivedDataPath(opts TestOptions) (string, error) {
	if opts.DerivedDataPath != "" {
		absolutePath, err := filepath.Abs(opts.DerivedDataPath)
		if err != nil {
			return "", fmt.Errorf("resolve derived data path: %w", err)
		}
		return filepath.Clean(absolutePath), nil
	}
	selector := opts.ProjectPath
	if selector == "" {
		selector = opts.WorkspacePath
	}
	absoluteSelector, err := filepath.Abs(selector)
	if err != nil {
		return "", fmt.Errorf("resolve Xcode project/workspace path: %w", err)
	}
	cacheDir, err := userCacheDirFn()
	if err != nil {
		return "", fmt.Errorf("resolve user cache directory for test derived data: %w", err)
	}
	cacheDir = strings.TrimSpace(cacheDir)
	if cacheDir == "" {
		return "", fmt.Errorf("resolve user cache directory for test derived data: empty path")
	}
	digest := sha256.Sum256([]byte(strings.Join(append([]string{
		absoluteSelector,
		opts.Scheme,
		opts.Action,
		opts.Configuration,
		opts.TestPlan,
	}, opts.Destinations...), "\x00")))
	hash := hex.EncodeToString(digest[:])[:12]
	return filepath.Join(cacheDir, "asc", "xcode-test", safeBuildPathComponent(opts.Scheme)+"-"+hash), nil
}

func resolveTestResultBundlePath(opts TestOptions) (string, error) {
	if opts.ResultBundlePath != "" {
		absolutePath, err := filepath.Abs(opts.ResultBundlePath)
		if err != nil {
			return "", fmt.Errorf("resolve result bundle path: %w", err)
		}
		return filepath.Clean(absolutePath), nil
	}
	cacheDir, err := userCacheDirFn()
	if err != nil {
		return "", fmt.Errorf("resolve user cache directory for test result bundle: %w", err)
	}
	cacheDir = strings.TrimSpace(cacheDir)
	if cacheDir == "" {
		return "", fmt.Errorf("resolve user cache directory for test result bundle: empty path")
	}
	now := testNowFn().UTC()
	selector := opts.ProjectPath
	if selector == "" {
		selector = opts.WorkspacePath
	}
	if selector == "" {
		selector = opts.XctestrunPath
	}
	digest := sha256.Sum256([]byte(strings.Join(append([]string{
		selector,
		opts.Scheme,
		opts.Action,
		opts.Configuration,
		opts.TestPlan,
	}, opts.Destinations...), "\x00")))
	hash := hex.EncodeToString(digest[:])[:12]
	stamp := strconv.FormatInt(now.UnixNano(), 10)
	return filepath.Join(cacheDir, "asc", "xcode-test", safeBuildPathComponent(opts.Scheme)+"-"+stamp+"-"+hash+".xcresult"), nil
}

func validateTestResultBundleDestination(pathValue string) error {
	if pathValue == "" {
		return nil
	}
	if _, err := os.Lstat(pathValue); err == nil {
		return fmt.Errorf("--result-bundle-path already exists: %s", pathValue)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect --result-bundle-path: %w", err)
	}
	return nil
}

func buildTestCommand(opts TestOptions) []string {
	args := make([]string, 0, 24+len(opts.Destinations)*2+len(opts.OnlyTesting)+len(opts.SkipTesting)+len(opts.XcodebuildArgs))
	if opts.WorkspacePath != "" {
		args = append(args, "-workspace", opts.WorkspacePath)
	}
	if opts.ProjectPath != "" {
		args = append(args, "-project", opts.ProjectPath)
	}
	if opts.Scheme != "" {
		args = append(args, "-scheme", opts.Scheme)
	}
	if opts.Configuration != "" {
		args = append(args, "-configuration", opts.Configuration)
	}
	for _, destination := range opts.Destinations {
		args = append(args, "-destination", destination)
	}
	if opts.TestPlan != "" {
		args = append(args, "-testPlan", opts.TestPlan)
	}
	if opts.XctestrunPath != "" {
		args = append(args, "-xctestrun", opts.XctestrunPath)
	}
	if opts.DerivedDataPath != "" {
		args = append(args, "-derivedDataPath", opts.DerivedDataPath)
	}
	if opts.ResultBundlePath != "" {
		args = append(args, "-resultBundlePath", opts.ResultBundlePath)
	}
	for _, identifier := range opts.OnlyTesting {
		args = append(args, "-only-testing:"+identifier)
	}
	for _, identifier := range opts.SkipTesting {
		args = append(args, "-skip-testing:"+identifier)
	}
	args = append(args, cloneStrings(opts.XcodebuildArgs)...)
	if opts.NoCodeSigning {
		args = append(args, "CODE_SIGNING_ALLOWED=NO")
	}
	if opts.Clean {
		args = append(args, "clean")
	}
	return append(args, opts.Action)
}

func reservedTestPassthroughArgument(args []string) string {
	if reserved := reservedBuildPassthroughArgument(args); reserved != "" {
		return reserved
	}
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		normalized := strings.ToLower(trimmed)
		for _, managed := range []string{"-testplan", "-xctestrun", "-only-testing", "-skip-testing"} {
			if normalized == managed || strings.HasPrefix(normalized, managed+"=") || strings.HasPrefix(normalized, managed+":") {
				return strings.SplitN(strings.SplitN(trimmed, "=", 2)[0], ":", 2)[0]
			}
		}
	}
	return ""
}

func setTestExitStatus(result *TestResult, err error) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitStatus := exitErr.ExitCode()
		if exitStatus >= 0 {
			result.ExitStatus = &exitStatus
		}
	}
}

func findXctestrunPath(derivedDataPath string) string {
	if strings.TrimSpace(derivedDataPath) == "" {
		return ""
	}
	productsPath := filepath.Join(derivedDataPath, "Build", "Products")
	entries, err := os.ReadDir(productsPath)
	if err != nil {
		return ""
	}
	candidates := make([]string, 0, 1)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.EqualFold(filepath.Ext(entry.Name()), ".xctestrun") {
			continue
		}
		candidates = append(candidates, filepath.Join(productsPath, entry.Name()))
	}
	if len(candidates) != 1 {
		return ""
	}
	return candidates[0]
}

func readTestResultSummary(ctx context.Context, resultBundlePath string) (*TestSummary, error) {
	if _, err := lookPathFn("xcrun"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("xcrun not available; install Xcode and ensure the active developer directory is configured")
		}
		return nil, fmt.Errorf("locate xcrun: %w", err)
	}
	summaryOutput, err := runXcresulttoolJSON(ctx, "summary", resultBundlePath)
	if err != nil {
		return nil, fmt.Errorf("run xcresulttool test-results summary: %w", err)
	}
	summary, err := ParseTestResultSummary(summaryOutput)
	if err != nil {
		return nil, err
	}

	// The summary operation contains aggregate counts and failure metadata, but
	// current Xcode versions expose individual test cases through the separate
	// `tests` operation. Keep that second read in the same post-processing step
	// so JSON and JUnit can report the structured test tree rather than parsing
	// human-readable xcodebuild output.
	testsOutput, err := runXcresulttoolJSON(ctx, "tests", resultBundlePath)
	if err != nil {
		return nil, fmt.Errorf("run xcresulttool test-results tests: %w", err)
	}
	cases, err := ParseTestResultCases(testsOutput)
	if err != nil {
		return nil, err
	}
	if summary.Total > 0 && len(cases) == 0 {
		return nil, fmt.Errorf("xcresulttool tests output did not include the %d reported test cases", summary.Total)
	}
	if len(cases) > 0 && len(cases) != summary.Total {
		return nil, fmt.Errorf("xcresulttool test case count %d does not match summary count %d", len(cases), summary.Total)
	}
	summary.Cases = cases
	for _, testCase := range cases {
		if normalizeTestStatus(testCase.Status) == "failed" && !containsTestFailure(summary.Failures, testCase.Identifier) {
			summary.Failures = append(summary.Failures, TestFailure{
				Identifier: testCase.Identifier,
				Message:    boundTestMessage(testCase.Message),
			})
		}
	}
	return summary, nil
}

func runXcresulttoolJSON(ctx context.Context, operation, resultBundlePath string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := commandContextFn(ctx, "xcrun", "xcresulttool", "get", "test-results", operation, "--path", resultBundlePath, "--compact")
	output, err := outputXcodeCommand(cmd)
	if err != nil {
		return nil, err
	}
	return output, nil
}

type rawTestResultSummary struct {
	Tests          json.RawMessage `json:"tests"`
	TestCases      json.RawMessage `json:"testCases"`
	TotalTestCount json.RawMessage `json:"totalTestCount"`
	PassedTests    json.RawMessage `json:"passedTests"`
	FailedTests    json.RawMessage `json:"failedTests"`
	SkippedTests   json.RawMessage `json:"skippedTests"`
	TestDuration   json.RawMessage `json:"testDuration"`
	Duration       json.RawMessage `json:"duration"`
	StartTime      json.RawMessage `json:"startTime"`
	FinishTime     json.RawMessage `json:"finishTime"`
	TestFailures   json.RawMessage `json:"testFailures"`
}

type rawTestFailure struct {
	Identifier       json.RawMessage `json:"testIdentifier"`
	IdentifierAlt    string          `json:"identifier"`
	IdentifierString string          `json:"testIdentifierString"`
	IdentifierURL    string          `json:"testIdentifierURL"`
	TestName         string          `json:"testName"`
	TargetName       string          `json:"targetName"`
	Message          string          `json:"message"`
	FailureMessage   string          `json:"failureMessage"`
	FailureText      string          `json:"failureText"`
}

type rawTestCase struct {
	Identifier     string          `json:"testIdentifier"`
	IdentifierAlt  string          `json:"identifier"`
	Name           string          `json:"name"`
	TestName       string          `json:"testName"`
	Classname      string          `json:"classname"`
	Status         string          `json:"status"`
	TestStatus     string          `json:"testStatus"`
	Result         string          `json:"result"`
	Duration       json.RawMessage `json:"duration"`
	DurationInSecs json.RawMessage `json:"durationInSeconds"`
	DurationMS     json.RawMessage `json:"durationMs"`
	Message        string          `json:"message"`
	FailureMessage string          `json:"failureMessage"`
}

type rawTestResults struct {
	TestNodes []rawTestNode `json:"testNodes"`
}

type rawTestNode struct {
	Identifier        string          `json:"nodeIdentifier"`
	IdentifierURL     string          `json:"nodeIdentifierURL"`
	IdentifierAlt     string          `json:"identifier"`
	NodeType          string          `json:"nodeType"`
	Name              string          `json:"name"`
	TestName          string          `json:"testName"`
	Status            string          `json:"status"`
	TestStatus        string          `json:"testStatus"`
	Result            string          `json:"result"`
	Duration          json.RawMessage `json:"duration"`
	DurationInSeconds json.RawMessage `json:"durationInSeconds"`
	Message           string          `json:"message"`
	FailureMessage    string          `json:"failureMessage"`
	Children          []rawTestNode   `json:"children"`
}

// ParseTestResultSummary parses the stable subset emitted by xcresulttool.
// It accepts both count-oriented summaries and summaries that include cases,
// because Xcode versions differ in how much detail they expose at this level.
func ParseTestResultSummary(data []byte) (*TestSummary, error) {
	var raw rawTestResultSummary
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode xcresulttool summary: %w", err)
	}
	cases, err := parseRawTestCasesPayload(raw.Tests)
	if err != nil {
		return nil, fmt.Errorf("decode test cases: %w", err)
	}
	if len(cases) == 0 {
		cases, err = parseRawTestCasesPayload(raw.TestCases)
		if err != nil {
			return nil, fmt.Errorf("decode test cases: %w", err)
		}
	}
	total, totalSet, err := decodeIntValue(raw.TotalTestCount)
	if err != nil {
		return nil, fmt.Errorf("decode test count: %w", err)
	}
	if !totalSet {
		total, totalSet, err = decodeIntValue(raw.Tests)
		if err != nil {
			return nil, fmt.Errorf("decode test count: %w", err)
		}
	}
	passed, passedSet, err := decodeIntValue(raw.PassedTests)
	if err != nil {
		return nil, fmt.Errorf("decode passed test count: %w", err)
	}
	failed, failedSet, err := decodeIntValue(raw.FailedTests)
	if err != nil {
		return nil, fmt.Errorf("decode failed test count: %w", err)
	}
	skipped, skippedSet, err := decodeIntValue(raw.SkippedTests)
	if err != nil {
		return nil, fmt.Errorf("decode skipped test count: %w", err)
	}
	if !totalSet && len(cases) > 0 {
		total = len(cases)
		totalSet = true
	}
	casePassed, caseFailed, caseSkipped := countTestCases(cases)
	if !passedSet {
		passed = casePassed
	}
	if !failedSet {
		failed = caseFailed
	}
	if !skippedSet {
		skipped = caseSkipped
	}
	if !totalSet {
		total = passed + failed + skipped
		if total == 0 {
			return nil, fmt.Errorf("xcresulttool summary did not include a test count")
		}
	}
	if len(cases) == 0 {
		missing := make([]string, 0, 4)
		if !totalSet {
			missing = append(missing, "totalTestCount")
		}
		if !passedSet {
			missing = append(missing, "passedTests")
		}
		if !failedSet {
			missing = append(missing, "failedTests")
		}
		if !skippedSet {
			missing = append(missing, "skippedTests")
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("xcresulttool summary is missing required test counts: %s", strings.Join(missing, ", "))
		}
	}
	if total < 0 || passed < 0 || failed < 0 || skipped < 0 || passed+failed+skipped > total {
		return nil, fmt.Errorf("xcresulttool summary contains inconsistent test counts")
	}
	durationMS, err := decodeDurationMS(raw.TestDuration)
	if err != nil {
		return nil, fmt.Errorf("decode test duration: %w", err)
	}
	if durationMS == 0 {
		durationMS, err = decodeDurationMS(raw.Duration)
		if err != nil {
			return nil, fmt.Errorf("decode test duration: %w", err)
		}
	}
	if durationMS == 0 {
		start, startSet, startErr := decodeFloatValue(raw.StartTime)
		finish, finishSet, finishErr := decodeFloatValue(raw.FinishTime)
		if startErr != nil || finishErr != nil {
			return nil, fmt.Errorf("decode test start/finish time: %w", errors.Join(startErr, finishErr))
		}
		if startSet && finishSet && finish >= start {
			durationMS = max(int64(0), int64((finish-start)*1000))
		}
	}
	failures, err := parseRawTestFailures(raw.TestFailures)
	if err != nil {
		return nil, fmt.Errorf("decode test failures: %w", err)
	}
	for _, testCase := range cases {
		if strings.EqualFold(testCase.Status, "failed") && len(failures) < maxTestFailureCount {
			if !containsTestFailure(failures, testCase.Identifier) {
				failures = append(failures, TestFailure{Identifier: testCase.Identifier, Message: boundTestMessage(testCase.Message)})
			}
		}
	}
	return &TestSummary{
		Total:      total,
		Passed:     passed,
		Failed:     failed,
		Skipped:    skipped,
		DurationMS: durationMS,
		Cases:      cases,
		Failures:   failures,
	}, nil
}

// ParseTestResultCases parses the recursive test tree returned by
// `xcresulttool get test-results tests`. Only Test Case nodes are exposed;
// suites, plans, devices, and failure-message children are structural.
func ParseTestResultCases(data []byte) ([]TestCase, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil, fmt.Errorf("xcresulttool tests output was empty")
	}
	if strings.HasPrefix(trimmed, "[") {
		var direct []rawTestCase
		if err := json.Unmarshal(data, &direct); err != nil {
			return nil, fmt.Errorf("decode xcresulttool test cases: %w", err)
		}
		return parseRawTestCases(direct)
	}

	var payload rawTestResults
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decode xcresulttool tests: %w", err)
	}
	if payload.TestNodes == nil {
		return nil, fmt.Errorf("xcresulttool tests output did not include testNodes")
	}
	cases := make([]TestCase, 0)
	for _, node := range payload.TestNodes {
		if err := appendTestCases(&cases, node); err != nil {
			return nil, err
		}
	}
	return cases, nil
}

func appendTestCases(cases *[]TestCase, node rawTestNode) error {
	if len(*cases) >= maxTestCaseCount {
		return fmt.Errorf("xcresulttool tests output exceeds %d test cases", maxTestCaseCount)
	}
	if strings.EqualFold(strings.TrimSpace(node.NodeType), "test case") {
		*cases = append(*cases, parseRawTestNode(node))
		return nil
	}
	for _, child := range node.Children {
		if err := appendTestCases(cases, child); err != nil {
			return err
		}
	}
	return nil
}

func parseRawTestCases(rawCases []rawTestCase) ([]TestCase, error) {
	if len(rawCases) > maxTestCaseCount {
		return nil, fmt.Errorf("xcresulttool tests output exceeds %d test cases", maxTestCaseCount)
	}
	cases := make([]TestCase, 0, len(rawCases))
	for _, rawCase := range rawCases {
		durationMS, err := decodeDurationMS(rawCase.DurationMS)
		if err != nil {
			return nil, err
		}
		if durationMS == 0 {
			durationMS, err = decodeDurationMS(rawCase.Duration)
			if err != nil {
				return nil, err
			}
		}
		if durationMS == 0 {
			durationMS, err = decodeDurationMS(rawCase.DurationInSecs)
			if err != nil {
				return nil, err
			}
		}
		identifier := strings.TrimSpace(rawCase.Identifier)
		if identifier == "" {
			identifier = strings.TrimSpace(rawCase.IdentifierAlt)
		}
		name := strings.TrimSpace(rawCase.Name)
		if name == "" {
			name = strings.TrimSpace(rawCase.TestName)
		}
		status := normalizeTestStatus(rawCase.TestStatus)
		if status == "" {
			status = normalizeTestStatus(rawCase.Status)
		}
		if status == "" {
			status = normalizeTestStatus(rawCase.Result)
		}
		message := rawCase.Message
		if strings.TrimSpace(message) == "" {
			message = rawCase.FailureMessage
		}
		cases = append(cases, TestCase{
			Identifier: identifier,
			Name:       name,
			Classname:  strings.TrimSpace(rawCase.Classname),
			Status:     status,
			DurationMS: durationMS,
			Message:    boundTestMessage(message),
		})
	}
	return cases, nil
}

func parseRawTestCasesPayload(data json.RawMessage) ([]TestCase, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var rawCases []rawTestCase
	if err := json.Unmarshal(data, &rawCases); err != nil {
		// A current summary uses no `tests` array, while older shapes may use an
		// object for that field. Treat an object as an absent case list so the
		// aggregate fields remain authoritative.
		return nil, nil
	}
	return parseRawTestCases(rawCases)
}

func parseRawTestNode(node rawTestNode) TestCase {
	identifier := strings.TrimSpace(node.Identifier)
	if identifier == "" {
		identifier = strings.TrimSpace(node.IdentifierAlt)
	}
	if identifier == "" {
		identifier = strings.TrimSpace(node.IdentifierURL)
	}
	name := strings.TrimSpace(node.Name)
	if name == "" {
		name = strings.TrimSpace(node.TestName)
	}
	status := normalizeTestStatus(node.TestStatus)
	if status == "" {
		status = normalizeTestStatus(node.Status)
	}
	if status == "" {
		status = normalizeTestStatus(node.Result)
	}
	durationMS, _ := decodeDurationMS(node.Duration)
	if durationMS == 0 {
		durationMS, _ = decodeDurationMS(node.DurationInSeconds)
	}
	message := node.Message
	if strings.TrimSpace(message) == "" {
		message = node.FailureMessage
	}
	if strings.TrimSpace(message) == "" {
		message = testNodeFailureMessage(node.Children)
	}
	return TestCase{
		Identifier: identifier,
		Name:       name,
		Classname:  testClassname(identifier),
		Status:     status,
		DurationMS: durationMS,
		Message:    boundTestMessage(message),
	}
}

func testNodeFailureMessage(children []rawTestNode) string {
	for _, child := range children {
		if strings.EqualFold(strings.TrimSpace(child.NodeType), "failure message") {
			message := child.Name
			if strings.TrimSpace(message) == "" {
				message = child.Message
			}
			if strings.TrimSpace(message) == "" {
				message = child.FailureMessage
			}
			if strings.TrimSpace(message) != "" {
				return boundTestMessage(message)
			}
		}
		if message := testNodeFailureMessage(child.Children); message != "" {
			return message
		}
	}
	return ""
}

func testClassname(identifier string) string {
	classname, _, ok := strings.Cut(identifier, "/")
	if !ok {
		return identifier
	}
	return classname
}

func parseRawTestFailures(data json.RawMessage) ([]TestFailure, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var rawFailures []rawTestFailure
	if err := json.Unmarshal(data, &rawFailures); err != nil {
		return nil, err
	}
	failures := make([]TestFailure, 0, min(len(rawFailures), maxTestFailureCount))
	for _, failure := range rawFailures {
		if len(failures) >= maxTestFailureCount {
			break
		}
		identifier := strings.TrimSpace(failure.IdentifierString)
		if identifier == "" {
			identifier = strings.TrimSpace(failure.IdentifierURL)
		}
		if identifier == "" {
			identifier = strings.TrimSpace(failure.IdentifierAlt)
		}
		if identifier == "" {
			identifier = decodeStringValue(failure.Identifier)
		}
		message := failure.FailureText
		if strings.TrimSpace(message) == "" {
			message = failure.Message
		}
		if strings.TrimSpace(message) == "" {
			message = failure.FailureMessage
		}
		failures = append(failures, TestFailure{Identifier: identifier, Message: boundTestMessage(message)})
	}
	return failures, nil
}

func decodeIntValue(data json.RawMessage) (int, bool, error) {
	if len(data) == 0 || string(data) == "null" {
		return 0, false, nil
	}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		return 0, false, nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err == nil {
		value, err := strconv.Atoi(string(number))
		if err != nil {
			return 0, false, err
		}
		return value, true, nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return 0, false, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return 0, false, err
	}
	return value, true, nil
}

func decodeStringValue(data json.RawMessage) string {
	if len(data) == 0 || string(data) == "null" {
		return ""
	}
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		return strings.TrimSpace(text)
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err == nil {
		return strings.TrimSpace(string(number))
	}
	return ""
}

func decodeFloatValue(data json.RawMessage) (float64, bool, error) {
	if len(data) == 0 || string(data) == "null" {
		return 0, false, nil
	}
	var number float64
	if err := json.Unmarshal(data, &number); err == nil {
		return number, true, nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return 0, false, err
	}
	number, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
	if err != nil {
		return 0, false, err
	}
	return number, true, nil
}

func decodeDurationMS(data json.RawMessage) (int64, error) {
	if len(data) == 0 || string(data) == "null" {
		return 0, nil
	}
	var number float64
	if err := json.Unmarshal(data, &number); err == nil {
		return max(int64(0), int64(number*1000)), nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(text)
	value, err := strconv.ParseFloat(trimmed, 64)
	if err == nil {
		return max(int64(0), int64(value*1000)), nil
	}
	parsed, durationErr := time.ParseDuration(strings.ReplaceAll(trimmed, " ", ""))
	if durationErr != nil {
		return 0, err
	}
	return max(int64(0), parsed.Milliseconds()), nil
}

func normalizeTestStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "passed", "pass", "success", "succeeded":
		return "passed"
	case "failed", "failure", "error", "errored":
		return "failed"
	case "skipped", "skip":
		return "skipped"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func countTestCases(cases []TestCase) (passed, failed, skipped int) {
	for _, testCase := range cases {
		switch normalizeTestStatus(testCase.Status) {
		case "passed":
			passed++
		case "failed":
			failed++
		case "skipped":
			skipped++
		}
	}
	return passed, failed, skipped
}

func boundTestMessage(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= maxTestFailureMessage {
		return value
	}
	return value[:maxTestFailureMessage]
}

func containsTestFailure(failures []TestFailure, identifier string) bool {
	for _, failure := range failures {
		if failure.Identifier == identifier && identifier != "" {
			return true
		}
	}
	return false
}
