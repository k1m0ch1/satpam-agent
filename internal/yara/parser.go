package yara

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Rule is a compiled YARA rule ready for matching.
type Rule struct {
	Name        string
	Description string
	Severity    string
	patterns    []pattern
	condition   condType
}

type condType int

const (
	condAny condType = iota
	condAll
)

type pattern struct {
	id     string
	lit    []byte
	re     *regexp.Regexp
	nocase bool
}

// ParseRules parses a block of YARA rule text into compiled Rules.
func ParseRules(text string) ([]*Rule, error) {
	var rules []*Rule
	sc := bufio.NewScanner(strings.NewReader(text))
	for {
		rule, err := nextRule(sc)
		if err != nil {
			return rules, err
		}
		if rule == nil {
			break
		}
		if len(rule.patterns) > 0 {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func nextRule(sc *bufio.Scanner) (*Rule, error) {
	var name string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "rule ") {
			name = strings.Fields(line)[1]
			break
		}
	}
	if name == "" {
		return nil, nil
	}

	rule := &Rule{Name: name, condition: condAny}
	section := ""

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line == "{" || strings.HasPrefix(line, "//"):
			continue
		case line == "}":
			return rule, nil
		case strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "$"):
			section = strings.TrimSuffix(line, ":")
		default:
			switch section {
			case "meta":
				parseMeta(rule, line)
			case "strings":
				if err := parseStringLine(rule, line); err != nil {
					return nil, fmt.Errorf("rule %s: %w", name, err)
				}
			case "condition":
				if strings.Contains(line, "all of") {
					rule.condition = condAll
				}
			}
		}
	}
	return rule, nil
}

func parseMeta(rule *Rule, line string) {
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return
	}
	v = strings.Trim(strings.TrimSpace(v), `"`)
	switch strings.TrimSpace(k) {
	case "description":
		rule.Description = v
	case "severity":
		rule.Severity = v
	}
}

var (
	reLit = regexp.MustCompile(`^\$(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(nocase)?`)
	reReg = regexp.MustCompile(`^\$(\w+)\s*=\s*/((?:[^\\/]|\\.)+)/([si]*)\s*(nocase)?`)
	reHex = regexp.MustCompile(`^\$(\w+)\s*=\s*\{\s*([0-9A-Fa-f\s]+)\}`)
)

func parseStringLine(rule *Rule, line string) error {
	if m := reLit.FindStringSubmatch(line); m != nil {
		nocase := m[3] == "nocase"
		val := unescapeYARA(m[2])
		p := pattern{id: m[1], nocase: nocase}
		if nocase {
			p.lit = bytes.ToLower([]byte(val))
		} else {
			p.lit = []byte(val)
		}
		rule.patterns = append(rule.patterns, p)
		return nil
	}
	if m := reReg.FindStringSubmatch(line); m != nil {
		prefix := ""
		if m[4] == "nocase" || strings.ContainsRune(m[3], 'i') {
			prefix = "(?i)"
		}
		re, err := regexp.Compile(prefix + m[2])
		if err != nil {
			return fmt.Errorf("bad regex %q: %w", m[2], err)
		}
		rule.patterns = append(rule.patterns, pattern{id: m[1], re: re})
		return nil
	}
	if m := reHex.FindStringSubmatch(line); m != nil {
		b, err := decodeHexPattern(m[2])
		if err != nil {
			return fmt.Errorf("bad hex pattern: %w", err)
		}
		rule.patterns = append(rule.patterns, pattern{id: m[1], lit: b})
		return nil
	}
	return nil
}

// Match returns whether data satisfies the rule. lower must be bytes.ToLower(data),
// computed once by the caller and shared across all rules for the same file.
func (r *Rule) Match(data, lower []byte) (matched bool, matchedOn, snippet string) {
	switch r.condition {
	case condAll:
		for _, p := range r.patterns {
			m, on, sn := p.match(data, lower)
			if !m {
				return false, "", ""
			}
			if matchedOn == "" {
				matchedOn, snippet = on, sn
			}
		}
		return true, matchedOn, snippet
	default:
		for _, p := range r.patterns {
			if m, on, sn := p.match(data, lower); m {
				return true, on, sn
			}
		}
		return false, "", ""
	}
}

func (p *pattern) match(data, lower []byte) (bool, string, string) {
	if p.re != nil {
		loc := p.re.FindIndex(data)
		if loc == nil {
			return false, "", ""
		}
		return true, "$" + p.id + " =~ /" + p.re.String() + "/", snip(data, loc[0], loc[1])
	}
	src := data
	if p.nocase {
		src = lower
	}
	idx := bytes.Index(src, p.lit)
	if idx < 0 {
		return false, "", ""
	}
	return true, "$" + p.id + " = " + string(p.lit), snip(data, idx, idx+len(p.lit))
}

const snippetPad = 30

func snip(data []byte, start, end int) string {
	lo := max(0, start-snippetPad)
	hi := min(len(data), end+snippetPad)
	src := data[lo:hi]
	out := make([]byte, len(src))
	for i, b := range src {
		if b >= 0x20 && b <= 0x7e {
			out[i] = b
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func unescapeYARA(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			out.WriteByte(s[i])
			i++
			continue
		}
		switch s[i+1] {
		case '"':
			out.WriteByte('"')
		case '\\':
			out.WriteByte('\\')
		case 't':
			out.WriteByte('\t')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 'x':
			if i+3 < len(s) {
				if b, err := hex.DecodeString(s[i+2 : i+4]); err == nil {
					out.WriteByte(b[0])
					i += 4
					continue
				}
			}
			out.WriteByte(s[i+1])
		default:
			out.WriteByte(s[i+1])
		}
		i += 2
	}
	return out.String()
}

// Strings returns the literal byte patterns in this rule (lowercase for nocase
// patterns, verbatim otherwise). Used by the scanner's speed-mode pre-filter.
func (r *Rule) Strings() [][]byte {
	var out [][]byte
	for _, p := range r.patterns {
		if p.lit != nil {
			out = append(out, p.lit)
		}
	}
	return out
}

func decodeHexPattern(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	return hex.DecodeString(clean)
}
