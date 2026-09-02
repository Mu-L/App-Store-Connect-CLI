package xcodecloud

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

// ciWorkflowCreateRelationships lists the relationships POST /v1/ciWorkflows requires.
var ciWorkflowCreateRelationships = []string{"product", "repository", "xcodeVersion", "macOsVersion"}

// ciWorkflowDuplicateDroppedAttributes lists attributes that a copy must not inherit:
// lastModifiedDate is response-only and CiWorkflowCreateRequest rejects it, and a copy is
// created unlocked so the operator can edit it, which is the point of duplicating.
var ciWorkflowDuplicateDroppedAttributes = []string{"lastModifiedDate", "isLockedForEditing"}

type ciWorkflowDuplicateOptions struct {
	name             string
	description      string
	overrideDescr    bool
	enabled          bool
	sourceWorkflowID string
}

// flagProvided reports whether a flag was set explicitly on the command line.
func flagProvided(fs *flag.FlagSet, name string) bool {
	provided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

// buildCiWorkflowDuplicatePayload turns a GET /v1/ciWorkflows/{id} envelope into a
// CiWorkflowCreateRequest body that recreates the same configuration under a new name.
func buildCiWorkflowDuplicatePayload(source json.RawMessage, opts ciWorkflowDuplicateOptions) (json.RawMessage, error) {
	var envelope struct {
		Data struct {
			Attributes    map[string]json.RawMessage `json:"attributes"`
			Relationships map[string]json.RawMessage `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(source, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse source workflow: %w", err)
	}

	attributes := map[string]json.RawMessage{}
	for key, value := range envelope.Data.Attributes {
		attributes[key] = value
	}
	for _, key := range ciWorkflowDuplicateDroppedAttributes {
		delete(attributes, key)
	}

	for _, key := range []string{"containerFilePath", "actions"} {
		if len(attributes[key]) == 0 {
			return nil, fmt.Errorf("source workflow %s is missing required attribute %q", opts.sourceWorkflowID, key)
		}
	}

	name, err := json.Marshal(opts.name)
	if err != nil {
		return nil, fmt.Errorf("failed to encode --name: %w", err)
	}
	attributes["name"] = name

	if opts.overrideDescr {
		description, err := json.Marshal(opts.description)
		if err != nil {
			return nil, fmt.Errorf("failed to encode --description: %w", err)
		}
		attributes["description"] = description
	} else if len(attributes["description"]) == 0 {
		attributes["description"] = json.RawMessage(`""`)
	}

	if opts.enabled {
		attributes["isEnabled"] = json.RawMessage("true")
	} else {
		attributes["isEnabled"] = json.RawMessage("false")
	}
	if len(attributes["clean"]) == 0 {
		attributes["clean"] = json.RawMessage("false")
	}

	relationships := map[string]json.RawMessage{}
	var missing []string
	for _, name := range ciWorkflowCreateRelationships {
		var relationship struct {
			Data *struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		}
		raw, ok := envelope.Data.Relationships[name]
		if ok {
			if err := json.Unmarshal(raw, &relationship); err != nil {
				return nil, fmt.Errorf("failed to parse source workflow relationship %q: %w", name, err)
			}
		}
		if relationship.Data == nil || strings.TrimSpace(relationship.Data.ID) == "" {
			missing = append(missing, name)
			continue
		}
		linkage, err := json.Marshal(map[string]any{
			"data": map[string]string{"type": relationship.Data.Type, "id": relationship.Data.ID},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to encode relationship %q: %w", name, err)
		}
		relationships[name] = linkage
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf(
			"source workflow %s did not include the %s relationship linkage required to create a copy",
			opts.sourceWorkflowID,
			strings.Join(missing, ", "),
		)
	}

	payload, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"type":          "ciWorkflows",
			"attributes":    attributes,
			"relationships": relationships,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode workflow payload: %w", err)
	}

	return payload, nil
}

// XcodeCloudWorkflowsDuplicateCommand returns the xcode-cloud workflows duplicate subcommand.
func XcodeCloudWorkflowsDuplicateCommand() *ffcli.Command {
	fs := flag.NewFlagSet("duplicate", flag.ExitOnError)

	id := fs.String("id", "", "Source workflow ID to copy")
	name := fs.String("name", "", "Name for the new workflow")
	description := fs.String("description", "", "Description for the new workflow (default: copied from the source workflow)")
	enabled := fs.Bool("enabled", false, "Enable the new workflow immediately; the copy is created disabled by default")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "duplicate",
		ShortUsage: "asc xcode-cloud workflows duplicate --id \"WORKFLOW_ID\" --name \"New Workflow\"",
		ShortHelp:  "Duplicate a workflow under a new name.",
		LongHelp: `Duplicate a workflow under a new name.

Reads the source workflow, then creates a new workflow in the same product with the
same start conditions, actions, environment, Xcode version, macOS version, and
repository. The copy is created disabled so it cannot start builds before it is
reviewed, and unlocked so it can be edited; pass --enabled to create it enabled.

TestFlight post-actions are not part of the public workflow schema, so they are not
copied.

Examples:
  asc xcode-cloud workflows duplicate --id "WORKFLOW_ID" --name "Nightly"
  asc xcode-cloud workflows duplicate --id "WORKFLOW_ID" --name "Nightly" --description "Nightly build"
  asc xcode-cloud workflows duplicate --id "WORKFLOW_ID" --name "Nightly" --enabled`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			idValue := strings.TrimSpace(*id)
			if idValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --id is required")
				return shared.MissingRequiredUsageError("--id")
			}
			nameValue := strings.TrimSpace(*name)
			if nameValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --name is required")
				return shared.MissingRequiredUsageError("--name")
			}

			client, err := shared.GetASCClient()
			if err != nil {
				return fmt.Errorf("xcode-cloud workflows duplicate: %w", err)
			}

			requestCtx, cancel := contextWithXcodeCloudTimeout(ctx, 0)
			defer cancel()

			source, err := client.GetCiWorkflowRaw(requestCtx, idValue, ciWorkflowCreateRelationships...)
			if err != nil {
				return fmt.Errorf("xcode-cloud workflows duplicate: failed to read source workflow: %w", err)
			}

			payload, err := buildCiWorkflowDuplicatePayload(source, ciWorkflowDuplicateOptions{
				name:             nameValue,
				description:      *description,
				overrideDescr:    flagProvided(fs, "description"),
				enabled:          *enabled,
				sourceWorkflowID: idValue,
			})
			if err != nil {
				return fmt.Errorf("xcode-cloud workflows duplicate: %w", err)
			}

			resp, err := client.CreateCiWorkflow(requestCtx, payload)
			if err != nil {
				return fmt.Errorf("xcode-cloud workflows duplicate: failed to create copy: %w", err)
			}

			return shared.PrintOutput(resp, *output.Output, *output.Pretty)
		},
	}
}
