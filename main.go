package main

import (
	"os"

	"github.com/hartfordfive/protologbeat/beater"
	"github.com/elastic/beats/libbeat/cmd"
)

func main() {
	var rootCmd = cmd.GenRootCmd("protologbeat", "0.2.0-beats6", beater.New)
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
