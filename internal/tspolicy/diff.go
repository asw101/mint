package tspolicy

import (
	"fmt"
	"strings"
)

// Unified renders a unified diff of two policy files.
//
// A diff is the whole safety story of `mint policy apply`: the operator is
// about to replace the file that decides who may reach what, and "here is the
// new file" is not something a person can check. Three lines of context is
// enough to see which grant a change lands in.
//
// The implementation is a plain longest-common-subsequence over lines. Policy
// files are hundreds of lines, not millions, so the quadratic table is free and
// the alternative is a dependency for something with one caller.
func Unified(oldName, newName string, oldText, newText []byte) string {
	oldLines := splitLines(string(oldText))
	newLines := splitLines(string(newText))
	ops := lcsOps(oldLines, newLines)

	hunks := group(ops, 3)
	if len(hunks) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", oldName, newName)
	for _, h := range hunks {
		var oldCount, newCount int
		for _, op := range h.ops {
			switch op.kind {
			case opEqual:
				oldCount++
				newCount++
			case opDelete:
				oldCount++
			case opInsert:
				newCount++
			}
		}
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", h.oldStart+1, oldCount, h.newStart+1, newCount)
		for _, op := range h.ops {
			switch op.kind {
			case opEqual:
				fmt.Fprintf(&b, " %s\n", op.text)
			case opDelete:
				fmt.Fprintf(&b, "-%s\n", op.text)
			case opInsert:
				fmt.Fprintf(&b, "+%s\n", op.text)
			}
		}
	}
	return b.String()
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type op struct {
	kind opKind
	text string
}

func lcsOps(a, b []string) []op {
	// table[i][j] is the length of the longest common subsequence of a[i:] and
	// b[j:], filled from the end so the walk forward below is a simple choice
	// between two neighbours.
	table := make([][]int, len(a)+1)
	for i := range table {
		table[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}

	var ops []op
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			ops = append(ops, op{opEqual, a[i]})
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			ops = append(ops, op{opDelete, a[i]})
			i++
		default:
			ops = append(ops, op{opInsert, b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		ops = append(ops, op{opDelete, a[i]})
	}
	for ; j < len(b); j++ {
		ops = append(ops, op{opInsert, b[j]})
	}
	return ops
}

type hunk struct {
	oldStart, newStart int
	ops                []op
}

// group collects runs of changes with up to context lines either side, so the
// output is the changed parts of the policy rather than the whole file.
func group(ops []op, context int) []hunk {
	// Mark every op within context lines of a change. Contiguous runs of marked
	// ops are the hunks.
	include := make([]bool, len(ops))
	var any bool
	for i, o := range ops {
		if o.kind == opEqual {
			continue
		}
		any = true
		lo := max(0, i-context)
		hi := min(len(ops)-1, i+context)
		for k := lo; k <= hi; k++ {
			include[k] = true
		}
	}
	if !any {
		return nil
	}

	// Line numbers are 0-based here and printed 1-based. Only equal and delete
	// ops advance the old file, only equal and insert the new one.
	oldLine, newLine := 0, 0
	var hunks []hunk
	for i := 0; i < len(ops); {
		if !include[i] {
			oldLine++
			newLine++
			i++
			continue
		}
		h := hunk{oldStart: oldLine, newStart: newLine}
		start := i
		for i < len(ops) && include[i] {
			switch ops[i].kind {
			case opEqual:
				oldLine++
				newLine++
			case opDelete:
				oldLine++
			case opInsert:
				newLine++
			}
			i++
		}
		h.ops = ops[start:i]
		hunks = append(hunks, h)
	}
	return hunks
}

// GrantsCapability reports whether a policy file's text mentions the given
// capability at all.
//
// This is a deliberately shallow check on the HuJSON source rather than a parse
// of the grants: the question it answers is "is the operator about to remove
// the grant that authorizes mint itself", and for that a false negative (the
// name is gone) is exactly what should stop the apply. Parsing to be sure which
// grant it appears in would make the check more precise and no more useful,
// since any answer here is followed by a human reading the diff.
func GrantsCapability(policy []byte, capability string) bool {
	return strings.Contains(string(policy), capability)
}
