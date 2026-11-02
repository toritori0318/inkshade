package inkshade_test

import (
	"fmt"
	"testing"

	"github.com/toritori0318/inkshade/pkg/inkshade"
)

func Example() {
	e := inkshade.NewEngine(inkshade.DefaultConfig())
	masked := e.Process("contact tanaka@example.com").Output
	fmt.Println(masked)
	// Output:
	// contact [EMAIL]
}

func TestAllowlistCompileFromOutside(t *testing.T) {
	cfg := inkshade.DefaultConfig()
	cfg.Allowlist = inkshade.Allowlist{
		Patterns: []string{`.*@example\.com`},
	}
	if err := cfg.Allowlist.Compile(); err != nil {
		t.Fatal(err)
	}

	e := inkshade.NewEngine(cfg)
	if findings := e.Detect("a@example.com"); len(findings) != 0 {
		t.Fatalf("allowlisted address still detected: %v", findings)
	}
	if findings := e.Detect("a@corp.io"); len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %v", len(findings), findings)
	}
}
