package actions

import (
	"context"
	"strings"
	"testing"
)

func TestCronListRejectsParameters(t *testing.T) {
	if _, err := noParamsCronList(context.Background(), map[string]any{"path": "/etc"}); err == nil {
		t.Fatal("cron.list must reject any parameter")
	}
}

func TestCronAddRejectsUnknownParams(t *testing.T) {
	if _, err := CronAdd(context.Background(), map[string]any{"line": "a", "path": "/x"}); err == nil {
		t.Fatal("cron.add must reject unknown parameters")
	}
}

func TestCronAddRejectsEmptyLine(t *testing.T) {
	if _, err := CronAdd(context.Background(), map[string]any{"line": "   "}); err == nil {
		t.Fatal("cron.add must reject an empty line")
	}
}

func TestCronAddRejectsControlChars(t *testing.T) {
	if _, err := CronAdd(context.Background(), map[string]any{"line": "0 4 * * * echo hi\nmalicious"}); err == nil {
		t.Fatal("cron.add must reject embedded newlines (NUL/CRLF control guard)")
	}
}

func TestCronRemoveRejectsUnknownParams(t *testing.T) {
	if _, err := CronRemove(context.Background(), map[string]any{"index": 0, "line": "x"}); err == nil {
		t.Fatal("cron.remove must reject unknown parameters")
	}
}

func TestCronToggleRejectsUnknownParams(t *testing.T) {
	if _, err := CronToggle(context.Background(), map[string]any{"index": 0, "line": "x"}); err == nil {
		t.Fatal("cron.toggle must reject unknown parameters")
	}
}

func TestCronToggleRejectsOutOfRangeIndex(t *testing.T) {
	// index way beyond any plausible crontab length must fail, not wrap.
	if _, err := CronToggle(context.Background(), map[string]any{"index": 999999}); err == nil {
		t.Fatal("cron.toggle must reject an out-of-range index")
	}
}

func TestCronRemoveRejectsOutOfRangeIndex(t *testing.T) {
	if _, err := CronRemove(context.Background(), map[string]any{"index": 999999}); err == nil {
		t.Fatal("cron.remove must reject an out-of-range index")
	}
}

func TestParseCrontabSchedulesAndCommands(t *testing.T) {
	raw := strings.Join([]string{
		"PATH=/usr/bin",
		"0 4 * * * /usr/bin/backup",
		"# 20 11 * * * /usr/bin/acme.sh --cron",
		"0 8 * * * cd /opt/horizon && docker compose run horizon",
	}, "\n")
	jobs := parseCrontab(raw)
	if len(jobs) != 4 {
		t.Fatalf("expected 4 entries (1 ENV + 1 enabled + 1 disabled + 1 enabled), got %d: %+v", len(jobs), jobs)
	}
	if jobs[0].Schedule != "" || jobs[0].Enabled {
		t.Fatalf("ENV line should be inert and enabled=true only for real entries: %+v", jobs[0])
	}
	if jobs[1].Schedule != "0 4 * * *" || jobs[1].Command != "/usr/bin/backup" {
		t.Fatalf("bad enabled job: %+v", jobs[1])
	}
	if jobs[2].Enabled {
		t.Fatalf("commented line should be disabled: %+v", jobs[2])
	}
	if !strings.Contains(jobs[2].Command, "acme.sh") {
		t.Fatalf("disabled command body lost: %+v", jobs[2])
	}
	if jobs[3].Schedule != "0 8 * * *" {
		t.Fatalf("bad schedule on last job: %+v", jobs[3])
	}
	for i, j := range jobs {
		if j.Index != i {
			t.Fatalf("index not sequential at %d: %+v", i, j)
		}
	}
}

func TestParseCrontabEmpty(t *testing.T) {
	jobs := parseCrontab("")
	if len(jobs) != 0 {
		t.Fatalf("expected no jobs, got %+v", jobs)
	}
}
