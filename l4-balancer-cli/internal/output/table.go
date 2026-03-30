package output

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type Table struct {
	headers []string
	rows    [][]string
	widths  []int
}

func NewTable(headers ...string) *Table {
	t := &Table{headers: headers, widths: make([]int, len(headers))}
	for i, h := range headers {
		t.widths[i] = utf8.RuneCountInString(h)
	}
	return t
}

func (t *Table) AddRow(cells ...string) {
	row := make([]string, len(t.headers))
	for i := range row {
		if i < len(cells) {
			row[i] = cells[i]
		}
		if w := utf8.RuneCountInString(row[i]); w > t.widths[i] {
			t.widths[i] = w
		}
	}
	t.rows = append(t.rows, row)
}

func (t *Table) Render(w io.Writer) {
	sep := t.separator()
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, t.formatRow(t.headers))
	fmt.Fprintln(w, sep)
	for _, row := range t.rows {
		fmt.Fprintln(w, t.formatRow(row))
	}
	fmt.Fprintln(w, sep)
}

func (t *Table) separator() string {
	parts := make([]string, len(t.widths))
	for i, w := range t.widths {
		parts[i] = strings.Repeat("-", w+2)
	}
	return "+" + strings.Join(parts, "+") + "+"
}

func (t *Table) formatRow(cells []string) string {
	parts := make([]string, len(t.widths))
	for i, w := range t.widths {
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		pad := w - utf8.RuneCountInString(cell)
		parts[i] = " " + cell + strings.Repeat(" ", pad+1)
	}
	return "|" + strings.Join(parts, "|") + "|"
}

func BoolMark(v bool) string {
	if v {
		return "v"
	}
	return "x"
}

func EnabledLabel(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

func OptionalStr(s *string) string {
	if s == nil {
		return "—"
	}
	return *s
}

func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func PrintSuccess(msg string) {
	fmt.Printf("\033[32m✓\033[0m %s\n", msg)
}

func PrintError(msg string) {
	fmt.Printf("\033[31m✗\033[0m %s\n", msg)
}

func PrintWarning(msg string) {
	fmt.Printf("\033[33m!\033[0m %s\n", msg)
}
