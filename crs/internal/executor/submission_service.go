package executor

import (
	"os"
	"strings"
)

func isSubmissionServiceDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("CRS_DISABLE_SUBMISSION_SERVICE")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func shouldUseSubmissionService(submissionEndpoint string) bool {
	if strings.TrimSpace(submissionEndpoint) == "" {
		return false
	}
	return !isSubmissionServiceDisabled()
}
