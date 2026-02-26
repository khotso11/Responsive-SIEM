package syslog

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	tsPattern           = regexp.MustCompile(`\bts=([0-9]{9,13})\b`)
	rfc3164HostPattern  = regexp.MustCompile(`^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+([^\s]+)\s+`) //nolint:lll
	rfc5424HostPattern  = regexp.MustCompile(`^(?:<\d{1,3}>\d\s+)\S+\s+([^\s]+)\s+`)
	invalidUserPattern  = regexp.MustCompile(`(?i)invalid user\s+([a-z0-9._-]+)`)
	failedForUserPatter = regexp.MustCompile(`(?i)failed password for(?: invalid user)?\s+([a-z0-9._-]+)`)
)

var severityMap = map[int]string{
	0: "emerg",
	1: "alert",
	2: "critical",
	3: "error",
	4: "warning",
	5: "notice",
	6: "info",
	7: "debug",
}

type parsed struct {
	Message      string
	Host         string
	User         string
	Severity     string
	EventType    string
	EventTSUnixM int64
}

func parseSyslogMessage(line string, recvTsUnixMs int64) parsed {
	msg := strings.TrimSpace(line)
	severity := "info"
	if strings.HasPrefix(msg, "<") {
		if end := strings.IndexByte(msg, '>'); end > 1 {
			if pri, err := strconv.Atoi(msg[1:end]); err == nil {
				if sev, ok := severityMap[pri%8]; ok {
					severity = sev
				}
			}
		}
	}
	host := ""
	if m := rfc3164HostPattern.FindStringSubmatch(msg); len(m) == 2 {
		host = strings.TrimSpace(m[1])
	} else if m := rfc5424HostPattern.FindStringSubmatch(msg); len(m) == 2 {
		host = strings.TrimSpace(m[1])
	}
	eventType := "syslog"
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "failed password") ||
		strings.Contains(lower, "invalid user") ||
		strings.Contains(lower, "authentication failure") {
		eventType = "auth_failed"
	}
	user := ""
	if m := invalidUserPattern.FindStringSubmatch(msg); len(m) == 2 {
		user = strings.TrimSpace(m[1])
	} else if m := failedForUserPatter.FindStringSubmatch(msg); len(m) == 2 {
		user = strings.TrimSpace(m[1])
	}
	eventTs := recvTsUnixMs
	if m := tsPattern.FindStringSubmatch(msg); len(m) == 2 {
		if parsedTs, ok := parseTSField(m[1]); ok {
			eventTs = parsedTs
		}
	}
	return parsed{
		Message:      msg,
		Host:         host,
		User:         user,
		Severity:     severity,
		EventType:    eventType,
		EventTSUnixM: eventTs,
	}
}

func parseTSField(raw string) (int64, bool) {
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	if v >= 1_000_000_000_000 {
		return v, true
	}
	return v * 1000, true
}
