package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "show version")
	mode := flag.String("mode", "mask", "mode: mask, detect, diagnose")
	configFile := flag.String("config", "", "config file (YAML)")
	disable := flag.String("disable", "", "comma-separated rule IDs to disable")
	replace := flag.String("replace", "", "custom replacements: email=[E],phone=[TEL]")
	format := flag.String("format", "text", "output format: text, json, ndjson")
	preset := flag.String("preset", "", "rule preset: jp-strict")
	maskStyle := flag.String("mask-style", "label", "mask style: label, partial, pseudo")
	dryRun := flag.Bool("dry-run", false, "show diff of changes without modifying")
	gitStaged := flag.Bool("git-staged", false, "scan git staged files")
	failOnDetect := flag.Bool("fail-on-detect", false, "exit 1 if sensitive data detected")
	output := flag.String("output", "", "output file (default: stdout)")
	flag.Parse()

	if *showVersion {
		fmt.Println("inkshade " + version)
		return
	}

	flagSet := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { flagSet[f.Name] = true })

	var cfg Config
	if *configFile != "" {
		var err error
		cfg, err = LoadConfig(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inkshade: %v\n", err)
			os.Exit(1)
		}
	} else {
		cfg = DefaultConfig()
	}

	if flagSet["mode"] || *configFile == "" {
		cfg.Mode = Mode(*mode)
	}

	if *disable != "" {
		for _, id := range strings.Split(*disable, ",") {
			cfg.Disabled[strings.TrimSpace(id)] = true
		}
	}

	if *replace != "" {
		for _, pair := range strings.Split(*replace, ",") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				cfg.Replacements[strings.TrimSpace(kv[0])] = kv[1]
			}
		}
	}

	if *preset != "" {
		cfg.EnabledPreset = *preset
	}

	switch Mode(*mode) {
	case ModeMask, ModeDetect, ModeDiagnose:
	default:
		fmt.Fprintf(os.Stderr, "inkshade: unknown mode %q (valid: mask, detect, diagnose)\n", *mode)
		os.Exit(1)
	}

	if err := ValidatePreset(cfg.EnabledPreset); err != nil {
		fmt.Fprintf(os.Stderr, "inkshade: %v\n", err)
		os.Exit(1)
	}

	if flagSet["mask-style"] || *configFile == "" {
		cfg.MaskStyle = MaskStyle(*maskStyle)
	}

	engine := NewEngine(cfg)

	if *dryRun && cfg.Mode != ModeMask {
		fmt.Fprintf(os.Stderr, "inkshade: --dry-run only works with mask mode\n")
		os.Exit(1)
	}

	if *gitStaged {
		os.Exit(processGitStaged(engine, cfg, *format, *dryRun, *failOnDetect, *output))
		return
	}

	var reader io.Reader
	if flag.NArg() > 0 {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "inkshade: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	} else {
		reader = os.Stdin
	}

	var writer io.Writer = os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inkshade: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		writer = f
	}

	filename := "<stdin>"
	if flag.NArg() > 0 {
		filename = flag.Arg(0)
	}

	var detected bool
	var scanErr error
	if *format == "sarif" {
		detected, scanErr = processSarif(engine, reader, writer, filename)
	} else {
		detected, scanErr = processReader(engine, cfg, reader, writer, *format, *dryRun)
	}

	if scanErr != nil {
		fmt.Fprintf(os.Stderr, "inkshade: %v\n", scanErr)
		os.Exit(2)
	}
	if *failOnDetect && detected {
		os.Exit(1)
	}
}

func processReader(engine *Engine, cfg Config, reader io.Reader, writer io.Writer, format string, dryRun bool) (bool, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 10*1024*1024)

	detected := false
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		result := engine.Process(line)

		if result.HasFindings {
			detected = true
		}

		if dryRun {
			diff := formatDryRunDiff(line, result.Output, lineNum)
			if diff != "" {
				fmt.Fprintln(writer, diff)
			}
			continue
		}

		switch cfg.Mode {
		case ModeMask:
			fmt.Fprintln(writer, result.Output)

		case ModeDetect:
			switch format {
			case "ndjson":
				rec := map[string]any{
					"line":         lineNum,
					"has_findings": result.HasFindings,
					"count":        len(result.Findings),
				}
				if result.HasFindings {
					rules := make([]string, 0, len(result.Findings))
					for _, f := range result.Findings {
						rules = append(rules, f.RuleID)
					}
					rec["rules"] = rules
				}
				b, _ := json.Marshal(rec)
				fmt.Fprintln(writer, string(b))
			default:
				if result.HasFindings {
					fmt.Fprintln(writer, "detected")
				} else {
					fmt.Fprintln(writer, "clean")
				}
			}

		case ModeDiagnose:
			switch format {
			case "ndjson", "json":
				for _, f := range result.Findings {
					rec := map[string]any{
						"line":    lineNum,
						"rule_id": f.RuleID,
						"name":    f.Name,
						"start":   f.Start,
						"end":     f.End,
						"text":    f.Text,
						"replace": f.Replace,
					}
					b, _ := json.Marshal(rec)
					fmt.Fprintln(writer, string(b))
				}
			default:
				for _, f := range result.Findings {
					fmt.Fprintf(writer, "line=%-4d rule=%-14s span=%d-%d  match=%q  replace=%q\n",
						lineNum, f.RuleID, f.Start, f.End, f.Text, f.Replace)
				}
			}
		}
	}

	return detected, scanner.Err()
}

func processSarif(engine *Engine, reader io.Reader, writer io.Writer, filename string) (bool, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 10*1024*1024)

	lines := map[int]lineData{}
	lineNum := 0
	detected := false

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		result := engine.Process(line)
		if result.HasFindings {
			detected = true
			lines[lineNum] = lineData{Findings: result.Findings, Text: result.Input}
		}
	}

	if err := scanner.Err(); err != nil {
		return detected, err
	}

	report := buildSarif(filename, lines)
	b, _ := json.MarshalIndent(report, "", "  ")
	fmt.Fprintln(writer, string(b))
	return detected, nil
}

func processGitStaged(engine *Engine, cfg Config, format string, dryRun bool, failOnDetect bool, outputPath string) int {
	toplevelOut, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "inkshade: git rev-parse failed: %v\n", err)
		return 1
	}
	repoRoot := strings.TrimSpace(string(toplevelOut))

	cmd := exec.Command("git", "diff", "--cached", "--name-only")
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "inkshade: git diff failed: %v\n", err)
		return 1
	}

	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(files) == 1 && files[0] == "" {
		fmt.Fprintln(os.Stderr, "inkshade: no staged files")
		return 0
	}

	var writer io.Writer = os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inkshade: %v\n", err)
			return 1
		}
		defer f.Close()
		writer = f
	}

	detected := false
	for _, file := range files {
		cleaned := filepath.Clean(file)
		abs := filepath.Join(repoRoot, cleaned)
		if !strings.HasPrefix(abs, repoRoot+string(filepath.Separator)) {
			fmt.Fprintf(os.Stderr, "inkshade: skipping path outside repo: %s\n", file)
			continue
		}

		blob, err := exec.Command("git", "show", ":"+cleaned).Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "inkshade: git show :%s failed: %v\n", cleaned, err)
			continue
		}

		reader := strings.NewReader(string(blob))

		if format == "sarif" {
			d, scanErr := processSarif(engine, reader, writer, file)
			if scanErr != nil {
				fmt.Fprintf(os.Stderr, "inkshade: %v\n", scanErr)
				return 2
			}
			if d {
				detected = true
			}
		} else {
			fmt.Fprintf(writer, "=== %s ===\n", file)
			d, scanErr := processReader(engine, cfg, reader, writer, format, dryRun)
			if scanErr != nil {
				fmt.Fprintf(os.Stderr, "inkshade: %v\n", scanErr)
				return 2
			}
			if d {
				detected = true
			}
		}
	}

	if failOnDetect && detected {
		return 1
	}
	return 0
}
