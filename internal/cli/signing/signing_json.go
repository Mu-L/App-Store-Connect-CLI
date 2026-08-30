package signing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type signingRunJSONFrame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
}

func rejectDuplicateSigningRunJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var stack []signingRunJSONFrame
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, signingRunJSONFrame{object: true, expectKey: true, keys: make(map[string]struct{})})
			case '[':
				stack = append(stack, signingRunJSONFrame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				markSigningRunJSONValueConsumed(stack)
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				current := &stack[len(stack)-1]
				// encoding/json matches tagged struct fields case-insensitively,
				// so BundleID silently overwrites bundleId during decoding. Fold
				// keys the same way here so a case-variant alias counts as the
				// duplicate it effectively is.
				for existing := range current.keys {
					if strings.EqualFold(existing, value) {
						return fmt.Errorf("duplicate JSON field %q", value)
					}
				}
				current.keys[value] = struct{}{}
				current.expectKey = false
			} else {
				markSigningRunJSONValueConsumed(stack)
			}
		default:
			markSigningRunJSONValueConsumed(stack)
		}
	}
}

func markSigningRunJSONValueConsumed(stack []signingRunJSONFrame) {
	if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
		stack[len(stack)-1].expectKey = true
	}
}
