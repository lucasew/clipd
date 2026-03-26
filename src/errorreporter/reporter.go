package errorreporter

import "log"

// Report is the centralized error reporting function for the project.
// All code paths that handle unexpected errors MUST funnel through this function.
func Report(err error, contextMsg string) {
	if err == nil {
		return
	}
	log.Printf("ERR %s: %s", contextMsg, err.Error())
}
