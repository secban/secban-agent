//nolint:gochecknoglobals,forbidigo // To be used in CLI.
package version

import (
	"fmt"
	"os"
)

// Version. Set at build time.
var Version string

func GetVersion() string {
	return Version
}

func CLI() {
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "-v" || args[0] == "--version") {
		fmt.Println(Version)
		os.Exit(0)
	}
}
