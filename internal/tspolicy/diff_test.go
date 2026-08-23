package tspolicy

import (
	"strings"
	"testing"
)

func TestUnifiedReportsNoChange(t *testing.T) {
	same := []byte("a\nb\nc\n")
	if got := Unified("old", "new", same, same); got != "" {
		t.Errorf("got %q, want no diff", got)
	}
}

func TestUnifiedShowsAReplacedLine(t *testing.T) {
	old := []byte("one\ntwo\nthree\n")
	updated := []byte("one\nTWO\nthree\n")

	got := Unified("tailnet", "policy.hujson", old, updated)
	want := strings.Join([]string{
		"--- tailnet",
		"+++ policy.hujson",
		"@@ -1,3 +1,3 @@",
		" one",
		"-two",
		"+TWO",
		" three",
		"",
	}, "\n")
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestUnifiedTrimsContextInALongFile(t *testing.T) {
	var oldLines, newLines []string
	for i := 0; i < 40; i++ {
		oldLines = append(oldLines, "line")
		newLines = append(newLines, "line")
	}
	newLines[20] = "changed"

	got := Unified("a", "b", []byte(strings.Join(oldLines, "\n")+"\n"), []byte(strings.Join(newLines, "\n")+"\n"))
	// Seven lines of body: three context either side of one change.
	if n := strings.Count(got, "\n"); n != 3+7+1 {
		t.Errorf("got %d lines, want a header, a hunk header and 8 body lines:\n%s", n, got)
	}
	if !strings.Contains(got, "+changed") {
		t.Errorf("the change is missing:\n%s", got)
	}
}

func TestUnifiedCapabilityRename(t *testing.T) {
	// The change this whole command exists to make.
	old := []byte(`{
  "grants": [
    {
      "src": ["tag:agent"],
      "dst": ["tag:tsapp"],
      "app": {"asw101.dev/cap/tsapp": [{"repos": ["*"]}]},
    },
  ],
}
`)
	updated := []byte(strings.ReplaceAll(string(old), "asw101.dev/cap/tsapp", "aaronw.dev/cap/mint"))

	got := Unified("tailnet", "policy.hujson", old, updated)
	if !strings.Contains(got, `-      "app": {"asw101.dev/cap/tsapp"`) {
		t.Errorf("the removed grant is missing:\n%s", got)
	}
	if !strings.Contains(got, `+      "app": {"aaronw.dev/cap/mint"`) {
		t.Errorf("the added grant is missing:\n%s", got)
	}
	// The destination tag is not part of this change and must not appear as one.
	if strings.Contains(got, `-      "dst": ["tag:tsapp"]`) {
		t.Errorf("the tag is unchanged and should not be in the diff:\n%s", got)
	}
}

func TestUnifiedHandlesAnEmptySide(t *testing.T) {
	got := Unified("a", "b", nil, []byte("one\ntwo\n"))
	if !strings.Contains(got, "+one") || !strings.Contains(got, "+two") {
		t.Errorf("got:\n%s", got)
	}
	got = Unified("a", "b", []byte("one\n"), nil)
	if !strings.Contains(got, "-one") {
		t.Errorf("got:\n%s", got)
	}
}

func TestUnifiedCountsLinesPerSide(t *testing.T) {
	// A hunk header that miscounts is worse than none: it is the part a reader
	// trusts to locate the change in the real file.
	old := []byte("a\nb\nc\nd\n")
	updated := []byte("a\nc\nd\ne\n")

	got := Unified("a", "b", old, updated)
	if !strings.Contains(got, "@@ -1,4 +1,4 @@") {
		t.Errorf("got:\n%s", got)
	}
}

func TestGrantsCapability(t *testing.T) {
	policy := []byte(`{"grants":[{"app":{"aaronw.dev/cap/mint":[{"repos":["*"]}]}}]}`)
	if !GrantsCapability(policy, "aaronw.dev/cap/mint") {
		t.Error("want the capability found")
	}
	if GrantsCapability(policy, "asw101.dev/cap/tsapp") {
		t.Error("want the old capability absent")
	}
}
