package xcode

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	xcconfigAssignmentPattern = regexp.MustCompile(`^(\s*)([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\r\n]+\])*)(\s*)(\+=|\?=|=)(\s*)(.*?)([ \t]*)$`)
	xcconfigIncludePattern    = regexp.MustCompile(`^\s*#include(\?)?\s+"([^"]+)"\s*$`)
)

type xcconfigAssignment struct {
	lineIndex     int
	key           string
	baseKey       string
	value         string
	operator      string
	quote         string
	operatorStart int
	operatorEnd   int
	valueStart    int
	valueEnd      int
	continued     bool
}

type xcconfigInclude struct {
	lineIndex int
	path      string
	optional  bool
}

type xcconfigDocument struct {
	lines       []string
	assignments []xcconfigAssignment
	includes    []xcconfigInclude
}

type xcconfigResolvedValue struct {
	value            string
	path             string
	found            bool
	exact            bool
	missingInherited bool
	conditionals     []xcconfigConditionalValue
}

type xcconfigConditionalValue struct {
	key      string
	value    string
	operator string
	path     string
}

func parseXCConfig(data []byte) (xcconfigDocument, error) {
	lines := splitLinesPreservingEndings(string(data))
	document := xcconfigDocument{lines: lines}
	inBlockComment := false

	for index, line := range lines {
		body := strings.TrimSuffix(line, "\n")
		body = strings.TrimSuffix(body, "\r")
		masked, nextInBlock := maskXCConfigComments(body, inBlockComment)
		inBlockComment = nextInBlock

		if matches := xcconfigIncludePattern.FindStringSubmatch(masked); matches != nil {
			document.includes = append(document.includes, xcconfigInclude{
				lineIndex: index,
				path:      matches[2],
				optional:  matches[1] == "?",
			})
			continue
		}

		indices := xcconfigAssignmentPattern.FindStringSubmatchIndex(masked)
		if indices == nil {
			continue
		}
		key := masked[indices[4]:indices[5]]
		operatorStart, operatorEnd := indices[8], indices[9]
		valueStart, valueEnd := indices[12], indices[13]
		value, quote, err := parseXCConfigValue(body[valueStart:valueEnd])
		if err != nil {
			return xcconfigDocument{}, fmt.Errorf("xcconfig line %d: %w", index+1, err)
		}
		document.assignments = append(document.assignments, xcconfigAssignment{
			lineIndex:     index,
			key:           key,
			baseKey:       xcconfigBaseKey(key),
			value:         value,
			operator:      body[operatorStart:operatorEnd],
			quote:         quote,
			operatorStart: operatorStart,
			operatorEnd:   operatorEnd,
			valueStart:    valueStart,
			valueEnd:      valueEnd,
			continued:     xcconfigValueHasLineContinuation(masked[valueStart:valueEnd]),
		})
	}

	if inBlockComment {
		return xcconfigDocument{}, fmt.Errorf("unterminated block comment in xcconfig")
	}
	return document, nil
}

func xcconfigValueHasLineContinuation(value string) bool {
	trimmed := strings.TrimRight(value, " \t")
	backslashes := 0
	for index := len(trimmed) - 1; index >= 0 && trimmed[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func parseXCConfigValue(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if err := validateXCConfigValueQuotes(value); err != nil {
		return "", "", err
	}
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1], string(value[0]), nil
	}
	return value, "", nil
}

func validateXCConfigValueQuotes(value string) error {
	var quote byte
	escaped := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if quote == 0 {
			if (character == '"' || character == '\'') && xcconfigQuoteStartsAt(value, index) {
				quote = character
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == quote {
			quote = 0
		}
	}
	if quote != 0 {
		return fmt.Errorf("unterminated quote %q in xcconfig value", string(quote))
	}
	return nil
}

func xcconfigQuoteStartsAt(value string, index int) bool {
	if index == 0 {
		return true
	}
	switch value[index-1] {
	case ' ', '\t', '=':
		return true
	default:
		return false
	}
}

func splitLinesPreservingEndings(value string) []string {
	if value == "" {
		return []string{""}
	}
	lines := strings.SplitAfter(value, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func maskXCConfigComments(line string, inBlockComment bool) (string, bool) {
	masked := []byte(line)
	inQuote := byte(0)
	escaped := false

	for index := 0; index < len(masked); index++ {
		if inBlockComment {
			masked[index] = ' '
			if index+1 < len(masked) && line[index] == '*' && line[index+1] == '/' {
				masked[index+1] = ' '
				index++
				inBlockComment = false
			}
			continue
		}

		character := line[index]
		if inQuote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == inQuote {
				inQuote = 0
			}
			continue
		}

		if (character == '"' || character == '\'') && xcconfigQuoteStartsAt(line, index) {
			inQuote = character
			continue
		}
		if index+1 >= len(masked) {
			continue
		}
		if line[index:index+2] == "//" {
			for rest := index; rest < len(masked); rest++ {
				masked[rest] = ' '
			}
			break
		}
		if line[index:index+2] == "/*" {
			masked[index] = ' '
			masked[index+1] = ' '
			index++
			inBlockComment = true
		}
	}
	return string(masked), inBlockComment
}

func xcconfigBaseKey(key string) string {
	if index := strings.Index(key, "["); index >= 0 {
		return key[:index]
	}
	return key
}

func resolveXCConfigInclude(containingPath string, include xcconfigInclude) (string, error) {
	if strings.Contains(include.path, "$(") || strings.Contains(include.path, "${") {
		return "", fmt.Errorf("xcconfig include contains unresolved build setting: %s", include.path)
	}
	path := include.path
	if filepath.Ext(path) == "" {
		path += ".xcconfig"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(containingPath), path)
	}
	return filepath.Clean(path), nil
}

func collectXCConfigFiles(root string) ([]string, error) {
	return collectXCConfigFilesWithReader(root, os.ReadFile, nil)
}

// collectXCConfigFilesWithReader walks an xcconfig include graph using the
// caller's reader and authorization hook. Security-sensitive callers should
// authorize every path before the reader or existence check touches it.
func collectXCConfigFilesWithReader(root string, read func(string) ([]byte, error), authorize func(string) error) ([]string, error) {
	return collectXCConfigFilesWithHooks(root, read, authorize, nil, nil)
}

// collectXCConfigFilesWithHooks is the instrumentable form of the collector.
// onPath runs for every normalized root or include target before authorization,
// stat, or read. onError receives the path responsible for a collection
// failure. Security-sensitive callers use these hooks to retain lexical
// provenance even when a path is missing or malformed and therefore never
// becomes part of the successfully collected file list.
func collectXCConfigFilesWithHooks(
	root string,
	read func(string) ([]byte, error),
	authorize func(string) error,
	onPath func(string),
	onError func(string, error),
) ([]string, error) {
	seen := make(map[string]bool)
	var paths []string
	var visit func(string, map[string]bool) (error, bool)
	visit = func(path string, stack map[string]bool) (error, bool) {
		path = filepath.Clean(path)
		pathKey := signingLexicalPathKey(path)
		if onPath != nil {
			onPath(path)
		}
		if stack[pathKey] || seen[pathKey] {
			return nil, false
		}
		if authorize != nil {
			if err := authorize(path); err != nil {
				if onError != nil {
					onError(path, err)
				}
				return err, false
			}
		}
		data, err := read(path)
		if err != nil {
			if onError != nil {
				onError(path, err)
			}
			return err, errors.Is(err, os.ErrNotExist)
		}
		document, err := parseXCConfig(data)
		if err != nil {
			if onError != nil {
				onError(path, err)
			}
			return fmt.Errorf("parse %s: %w", path, err), false
		}
		seen[pathKey] = true
		paths = append(paths, path)
		nextStack := clonePathSet(stack)
		nextStack[pathKey] = true
		var includeErrors []error
		for _, include := range document.includes {
			includePath, err := resolveXCConfigInclude(path, include)
			if err != nil {
				if onError != nil {
					onError(path, err)
				}
				includeErrors = append(includeErrors, err)
				continue
			}
			// Let the same authorization-aware reader perform existence and type
			// checks. In particular, never stat an include before the authorization
			// hook has accepted its lexical path. Optional missing includes are the
			// one intentional not-exist case and are ignored after that check.
			childErr, missingTarget := visit(includePath, nextStack)
			if childErr != nil {
				if include.optional && missingTarget {
					continue
				}
				includeErrors = append(includeErrors, childErr)
			}
		}
		if len(includeErrors) == 1 {
			return includeErrors[0], false
		}
		if len(includeErrors) > 1 {
			return errors.Join(includeErrors...), false
		}
		return nil, false
	}
	if err, _ := visit(root, make(map[string]bool)); err != nil {
		return nil, err
	}
	return paths, nil
}

func resolveXCConfigSetting(root, setting string) (xcconfigResolvedValue, error) {
	return resolveXCConfigSettingWithBase(root, setting, xcconfigResolvedValue{})
}

func resolveXCConfigSettingWithBase(root, setting string, base xcconfigResolvedValue) (xcconfigResolvedValue, error) {
	return resolveXCConfigSettingWithBaseReader(root, setting, base, os.ReadFile, os.Stat)
}

func resolveXCConfigSettingWithBaseReader(
	root, setting string,
	base xcconfigResolvedValue,
	read func(string) ([]byte, error),
	stat func(string) (os.FileInfo, error),
) (xcconfigResolvedValue, error) {
	resolved, conditional, err := resolveXCConfigSettingRecursiveWithReader(
		filepath.Clean(root), setting, make(map[string]bool), base, read, stat,
	)
	if err != nil {
		return xcconfigResolvedValue{}, err
	}
	if !resolved.exact && conditional {
		return xcconfigResolvedValue{}, fmt.Errorf(
			"%s is defined only by conditional xcconfig assignments; SDK-aware resolution requires Xcode",
			setting,
		)
	}
	if resolved.exact {
		for _, conditionalValue := range resolved.conditionals {
			if conditionalValue.operator != "=" || strings.TrimSpace(conditionalValue.value) != strings.TrimSpace(resolved.value) {
				return xcconfigResolvedValue{}, fmt.Errorf(
					"%s has differing conditional xcconfig assignment %s %s %q in %s (unconditional value %q); narrow the scope or use Xcode-aware resolution",
					setting,
					conditionalValue.key,
					conditionalValue.operator,
					conditionalValue.value,
					conditionalValue.path,
					resolved.value,
				)
			}
		}
	}
	if resolved.missingInherited {
		return xcconfigResolvedValue{}, fmt.Errorf("%s uses $(inherited) without a lower-layer value", setting)
	}
	return resolved, nil
}

func resolveXCConfigSettingRecursiveWithReader(
	path string,
	setting string,
	stack map[string]bool,
	resolved xcconfigResolvedValue,
	read func(string) ([]byte, error),
	stat func(string) (os.FileInfo, error),
) (xcconfigResolvedValue, bool, error) {
	path = filepath.Clean(path)
	pathKey := signingLexicalPathKey(path)
	if stack[pathKey] {
		return resolved, false, nil
	}
	data, err := read(path)
	if err != nil {
		return xcconfigResolvedValue{}, false, err
	}
	document, err := parseXCConfig(data)
	if err != nil {
		return xcconfigResolvedValue{}, false, fmt.Errorf("parse %s: %w", path, err)
	}
	nextStack := clonePathSet(stack)
	nextStack[pathKey] = true

	type event struct {
		line       int
		assignment *xcconfigAssignment
		include    *xcconfigInclude
	}
	var events []event
	for index := range document.assignments {
		assignment := &document.assignments[index]
		events = append(events, event{line: assignment.lineIndex, assignment: assignment})
	}
	for index := range document.includes {
		include := &document.includes[index]
		events = append(events, event{line: include.lineIndex, include: include})
	}
	sort.SliceStable(events, func(left, right int) bool {
		return events[left].line < events[right].line
	})

	conditionalFound := false
	for _, item := range events {
		if item.include != nil {
			includePath, err := resolveXCConfigInclude(path, *item.include)
			if err != nil {
				return xcconfigResolvedValue{}, false, err
			}
			if _, err := stat(includePath); err != nil {
				if item.include.optional && os.IsNotExist(err) {
					continue
				}
				return xcconfigResolvedValue{}, false, fmt.Errorf("read xcconfig include %s: %w", includePath, err)
			}
			included, includedConditional, err := resolveXCConfigSettingRecursiveWithReader(includePath, setting, nextStack, resolved, read, stat)
			if err != nil {
				return xcconfigResolvedValue{}, false, err
			}
			resolved = included
			conditionalFound = conditionalFound || includedConditional
			continue
		}

		assignment := item.assignment
		if assignment.baseKey != setting {
			continue
		}
		if assignment.key != setting {
			conditionalFound = true
			resolved.conditionals = append(resolved.conditionals, xcconfigConditionalValue{
				key:      assignment.key,
				value:    assignment.value,
				operator: assignment.operator,
				path:     path,
			})
			continue
		}
		value := assignment.value
		hadLowerValue := resolved.found
		hasInherited := strings.Contains(value, "$(inherited)") || strings.Contains(value, "${inherited}")
		value = strings.ReplaceAll(value, "$(inherited)", resolved.value)
		value = strings.ReplaceAll(value, "${inherited}", resolved.value)
		switch assignment.operator {
		case "?=":
			if resolved.found {
				continue
			}
		case "+=":
			if !hasInherited {
				value = strings.TrimSpace(strings.TrimSpace(resolved.value) + " " + strings.TrimSpace(value))
			}
		}
		resolved = xcconfigResolvedValue{
			value:            strings.TrimSpace(value),
			path:             path,
			found:            true,
			exact:            true,
			missingInherited: hasInherited && !hadLowerValue,
			conditionals:     resolved.conditionals,
		}
	}
	return resolved, conditionalFound, nil
}

func editXCConfig(data []byte, setting, value string) ([]byte, []string, bool, error) {
	document, err := parseXCConfig(data)
	if err != nil {
		return nil, nil, false, err
	}
	assignmentsByLine := make(map[int]xcconfigAssignment)
	var oldValues []string
	for _, assignment := range document.assignments {
		if assignment.baseKey != setting {
			continue
		}
		assignmentsByLine[assignment.lineIndex] = assignment
		oldValues = append(oldValues, assignment.value)
	}
	if len(assignmentsByLine) == 0 {
		return data, nil, false, nil
	}

	changed := false
	for index, assignment := range assignmentsByLine {
		line := document.lines[index]
		if assignment.value == value && assignment.operator == "=" {
			continue
		}
		quotedValue := quoteXCConfigValue(value, assignment.quote)
		document.lines[index] = line[:assignment.operatorStart] + "=" +
			line[assignment.operatorEnd:assignment.valueStart] + quotedValue + line[assignment.valueEnd:]
		changed = true
	}
	return []byte(strings.Join(document.lines, "")), oldValues, changed, nil
}

func quoteXCConfigValue(value, quote string) string {
	if quote == "" {
		return value
	}
	var encoded strings.Builder
	encoded.Grow(len(value) + len(quote)*2)
	encoded.WriteString(quote)
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '\\' || character == quote[0] {
			encoded.WriteByte('\\')
		}
		encoded.WriteByte(character)
	}
	encoded.WriteString(quote)
	return encoded.String()
}

func clonePathSet(source map[string]bool) map[string]bool {
	clone := make(map[string]bool, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
