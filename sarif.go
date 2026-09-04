package main

import (
	"sort"
	"unicode/utf8"
)

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

type lineData struct {
	Findings []Finding
	Text     string
}

func byteOffsetToRuneOffset(s string, byteOff int) int {
	return utf8.RuneCountInString(s[:byteOff])
}

func buildSarif(filename string, lines map[int]lineData) sarifReport {
	return buildSarifWithVersion(filename, lines, version)
}

func buildSarifWithVersion(filename string, lines map[int]lineData, ver string) sarifReport {
	lineNums := make([]int, 0, len(lines))
	for n := range lines {
		lineNums = append(lineNums, n)
	}
	sort.Ints(lineNums)

	var results []sarifResult
	for _, lineNum := range lineNums {
		ld := lines[lineNum]
		for _, f := range ld.Findings {
			startCol := byteOffsetToRuneOffset(ld.Text, f.Start) + 1
			endCol := byteOffsetToRuneOffset(ld.Text, f.End) + 1
			results = append(results, sarifResult{
				RuleID:  f.RuleID,
				Message: sarifMessage{Text: f.Name + " detected"},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{URI: filename},
							Region: sarifRegion{
								StartLine:   lineNum,
								StartColumn: startCol,
								EndColumn:   endCol,
							},
						},
					},
				},
			})
		}
	}

	return sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "inkshade",
						Version: ver,
					},
				},
				Results: results,
			},
		},
	}
}
