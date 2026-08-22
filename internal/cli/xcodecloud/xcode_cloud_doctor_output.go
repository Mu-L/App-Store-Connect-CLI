package xcodecloud

import (
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func printXcodeCloudDoctorResult(result *asc.XcodeCloudDoctorResult, output string, pretty bool) error {
	return shared.PrintOutput(result, output, pretty)
}
