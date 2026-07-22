package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/PastureStack/ipsec-vxlan-overlay-network/internal/topology"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ipsec-vxlan-overlay-network", flag.ContinueOnError)
	flags.SetOutput(stderr)
	filePath := flags.String("file", "", "read topology JSON from this file instead of standard input")
	showVersion := flags.Bool("version", false, "print the build version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	input := stdin
	var file *os.File
	if *filePath != "" {
		var err error
		file, err = os.Open(*filePath)
		if err != nil {
			fmt.Fprintln(stderr, "unable to open input file")
			return 1
		}
		defer file.Close()
		input = file
	}

	config, err := topology.Decode(input)
	if err != nil {
		fmt.Fprintf(stderr, "invalid topology document: %v\n", err)
		return 1
	}
	plan, err := topology.BuildPlan(config)
	if err != nil {
		fmt.Fprintf(stderr, "invalid topology: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plan); err != nil {
		fmt.Fprintln(stderr, "unable to encode plan")
		return 1
	}
	return 0
}
