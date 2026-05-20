package yara

import (
	"bytes"
	"testing"
)

const (
	testMarker = "SATPAM_UNIT_TEST_CANARY_XZ42"

	minimalRule = `
rule Test_SatpamCanary {
    meta:
        description = "synthetic satpam unit-test marker"
        severity = "high"
    strings:
        $s1 = "SATPAM_UNIT_TEST_CANARY_XZ42" nocase
    condition:
        any of them
}
`
)

func TestParseRules_ReturnsOneRule(t *testing.T) {
	rules, err := ParseRules(minimalRule)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "Test_SatpamCanary" {
		t.Errorf("name: got %q, want %q", rules[0].Name, "Test_SatpamCanary")
	}
	if rules[0].Severity != "high" {
		t.Errorf("severity: got %q, want %q", rules[0].Severity, "high")
	}
}

func TestParseRules_EmptyInput(t *testing.T) {
	rules, err := ParseRules("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestParseRules_IgnoresRulesWithNoStrings(t *testing.T) {
	src := `
rule Empty_Rule {
    meta:
        severity = "low"
    condition:
        true
}
`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("rule with no strings should be dropped; got %d rules", len(rules))
	}
}

func TestParseRules_CommentsIgnored(t *testing.T) {
	src := `
// top-level comment
rule Test_Commented {
    meta:
        severity = "medium"
    strings:
        // inline comment
        $s1 = "SATPAM_COMMENT_TEST"
    condition:
        any of them
}
`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestMatch_Literal_Nocase_Hit(t *testing.T) {
	rules, _ := ParseRules(minimalRule)
	rule := rules[0]

	data := []byte("PREFIX " + testMarker + " SUFFIX")
	lower := bytes.ToLower(data)
	matched, on, _ := rule.Match(data, lower)
	if !matched {
		t.Error("expected match on testMarker, got none")
	}
	if on == "" {
		t.Error("matchedOn should not be empty")
	}
}

func TestMatch_Literal_Nocase_Uppercase(t *testing.T) {
	rules, _ := ParseRules(minimalRule)
	rule := rules[0]

	data := []byte("satpam_unit_test_canary_xz42")
	lower := bytes.ToLower(data)
	matched, _, _ := rule.Match(data, lower)
	if !matched {
		t.Error("nocase: lowercase variant should match")
	}
}

func TestMatch_Literal_Nocase_Miss(t *testing.T) {
	rules, _ := ParseRules(minimalRule)
	rule := rules[0]

	data := []byte("completely safe content with no markers")
	lower := bytes.ToLower(data)
	matched, _, _ := rule.Match(data, lower)
	if matched {
		t.Error("expected no match on clean content, got one")
	}
}

func TestParseRules_HexPattern(t *testing.T) {
	src := `
rule Test_Hex {
    meta:
        severity = "critical"
    strings:
        $h1 = { 53 41 54 50 41 4D }
    condition:
        any of them
}
`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	data := []byte("SATPAM_UNIT_TEST")
	lower := bytes.ToLower(data)
	matched, _, _ := rules[0].Match(data, lower)
	if !matched {
		t.Error("hex pattern should match 'SATPAM'")
	}
}

func TestParseRules_HexPattern_Miss(t *testing.T) {
	src := `
rule Test_Hex_Miss {
    meta:
        severity = "low"
    strings:
        $h1 = { 53 41 54 50 41 4D }
    condition:
        any of them
}
`
	rules, _ := ParseRules(src)
	data := []byte("nothing here")
	lower := bytes.ToLower(data)
	if m, _, _ := rules[0].Match(data, lower); m {
		t.Error("should not match content without SATPAM bytes")
	}
}

func TestParseRules_RegexPattern(t *testing.T) {
	src := `
rule Test_Regex {
    meta:
        severity = "high"
    strings:
        $r1 = /SATPAM_\w+/ nocase
    condition:
        any of them
}
`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0]

	data := []byte("payload contains SATPAM_CANARY here")
	lower := bytes.ToLower(data)
	if matched, _, _ := rule.Match(data, lower); !matched {
		t.Error("regex should match SATPAM_ prefix")
	}

	data2 := []byte("nothing to see")
	lower2 := bytes.ToLower(data2)
	if matched, _, _ := rule.Match(data2, lower2); matched {
		t.Error("regex should not match clean content")
	}
}

func TestParseRules_CondAll_RequiresBoth(t *testing.T) {
	src := `
rule Test_CondAll {
    meta:
        severity = "high"
    strings:
        $s1 = "ALPHA_MARKER"
        $s2 = "BETA_MARKER"
    condition:
        all of them
}
`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0]

	d1 := []byte("only ALPHA_MARKER present")
	if m, _, _ := rule.Match(d1, bytes.ToLower(d1)); m {
		t.Error("condAll with only $s1 should not match")
	}

	d2 := []byte("both ALPHA_MARKER and BETA_MARKER present")
	if m, _, _ := rule.Match(d2, bytes.ToLower(d2)); !m {
		t.Error("condAll with both strings should match")
	}
}

func TestParseRules_CondAll_CapturesFirstMatch(t *testing.T) {
	src := `
rule Test_CondAll_First {
    meta:
        severity = "high"
    strings:
        $s1 = "FIRST_TOKEN"
        $s2 = "SECOND_TOKEN"
    condition:
        all of them
}
`
	rules, _ := ParseRules(src)
	rule := rules[0]
	data := []byte("FIRST_TOKEN and then SECOND_TOKEN appear")
	matched, on, _ := rule.Match(data, bytes.ToLower(data))
	if !matched {
		t.Fatal("expected match")
	}
	if on == "" {
		t.Error("matchedOn should not be empty for condAll")
	}
}

func TestParseRules_MultipleRules(t *testing.T) {
	src := `
rule Rule_Alpha {
    meta:
        severity = "high"
    strings:
        $a = "ALPHA_SIGNAL_99"
    condition:
        any of them
}

rule Rule_Beta {
    meta:
        severity = "critical"
    strings:
        $b = "BETA_SIGNAL_99"
    condition:
        any of them
}
`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestSnip_MidFile(t *testing.T) {
	data := []byte("the quick brown fox jumps over the lazy dog")
	if result := snip(data, 16, 19); result == "" {
		t.Error("snip returned empty string")
	}
}

func TestSnip_AtStart(t *testing.T) {
	data := []byte("SATPAM_MARKER is at the very start")
	if result := snip(data, 0, 6); result == "" {
		t.Error("snip at file start returned empty")
	}
}

func TestSnip_AtEnd(t *testing.T) {
	data := []byte("content ends with SATPAM")
	if result := snip(data, len(data)-6, len(data)); result == "" {
		t.Error("snip at file end returned empty")
	}
}

func TestUnescapeYARA_Tab(t *testing.T) {
	if got := unescapeYARA(`a\tb`); got != "a\tb" {
		t.Errorf("tab: got %q, want %q", got, "a\tb")
	}
}

func TestUnescapeYARA_Newline(t *testing.T) {
	if got := unescapeYARA(`a\nb`); got != "a\nb" {
		t.Errorf("newline: got %q, want %q", got, "a\nb")
	}
}

func TestUnescapeYARA_Hex(t *testing.T) {
	if got := unescapeYARA(`\x41`); got != "A" {
		t.Errorf("hex: got %q, want A", got)
	}
}

func TestUnescapeYARA_Quote(t *testing.T) {
	if got := unescapeYARA(`say \"hi\"`); got != `say "hi"` {
		t.Errorf("quote: got %q", got)
	}
}

func TestUnescapeYARA_NoEscape(t *testing.T) {
	if got := unescapeYARA("plain text"); got != "plain text" {
		t.Errorf("plain: got %q", got)
	}
}
