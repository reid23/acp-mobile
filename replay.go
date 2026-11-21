package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
	"unicode/utf8"
)

const (
	// replayBudget bounds the history sent to the phone on connect;
	// ?history=all lifts it.
	replayBudget = 2 << 20
	// Tool calls bigger than this have their long strings cut in replays.
	maxToolLine = 24 << 10
	// Length long strings are cut to.
	maxToolString = 4 << 10

	// Older acp-multiplex builds don't mark the end of the replay; it's
	// over when the socket goes quiet, or after legacyReplayMax.
	legacyReplayIdle = 250 * time.Millisecond
	legacyReplayMax  = 3 * time.Second
)

// replayState is the session state acp-multiplex reports in its
// replay_begin / replay_end / status notifications.
type replayState struct {
	State    string            `json:"state"` // idle, working, awaiting_input
	Since    int64             `json:"since,omitempty"`
	Awaiting []json.RawMessage `json:"awaiting"` // ids of reverse calls waiting on a person
	// Legacy is set when the state was inferred from history because the
	// multiplexer predates state reporting.
	Legacy bool `json:"legacy,omitempty"`
}

// lineReader splits a socket stream into lines. Returned lines alias its
// buffer but are never overwritten.
type lineReader struct {
	conn net.Conn
	buf  []byte
	tmp  []byte
}

func newLineReader(conn net.Conn) *lineReader {
	return &lineReader{conn: conn, tmp: make([]byte, 256*1024)}
}

// next returns the next non-empty line. A zero deadline means none.
func (r *lineReader) next(deadline time.Time) ([]byte, error) {
	for {
		if nl := bytes.IndexByte(r.buf, '\n'); nl >= 0 {
			line := r.buf[:nl:nl]
			r.buf = r.buf[nl+1:]
			if len(line) == 0 {
				continue
			}
			return line, nil
		}
		r.conn.SetReadDeadline(deadline)
		n, err := r.conn.Read(r.tmp)
		r.buf = append(r.buf, r.tmp[:n]...)
		if err != nil && n == 0 {
			return nil, err
		}
	}
}

// lineMethod returns the JSON-RPC method of line, or "" for responses.
func lineMethod(line []byte) string {
	var m struct {
		Method string `json:"method"`
	}
	json.Unmarshal(line, &m)
	return m.Method
}

// markerMethod is lineMethod for acp-multiplex's own notifications only,
// skipping the JSON parse for everything else.
func markerMethod(line []byte) string {
	if !bytes.Contains(line, []byte(`"acp-multiplex/`)) {
		return ""
	}
	return lineMethod(line)
}

func isHeaderLine(line []byte) bool {
	m := lineMethod(line)
	return m == "" || m == "acp-multiplex/meta"
}

func isTimeout(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// readReplay reads the history acp-multiplex replays to a new connection.
// With headerOnly it stops after the session header (meta, initialize and
// session/new responses), which is all the session list needs.
func readReplay(r *lineReader, timeout time.Duration, headerOnly bool) ([][]byte, replayState, error) {
	start := time.Now()
	var lines [][]byte
	var st replayState
	marked := false
	for {
		deadline := start.Add(timeout)
		if !marked {
			deadline = start.Add(legacyReplayMax)
			if idle := time.Now().Add(legacyReplayIdle); idle.Before(deadline) {
				deadline = idle
			}
		}
		line, err := r.next(deadline)
		if err != nil {
			if !marked && isTimeout(err) {
				return lines, legacyState(lines), nil
			}
			return lines, st, err
		}
		switch markerMethod(line) {
		case "acp-multiplex/replay_begin":
			if !marked && len(lines) == 0 {
				marked = true
				st = parseState(line)
				continue
			}
		case "acp-multiplex/replay_end":
			if marked {
				return lines, parseState(line), nil
			}
		}
		if marked && headerOnly && !isHeaderLine(line) {
			return lines, st, nil
		}
		lines = append(lines, line)
	}
}

func parseState(line []byte) replayState {
	var m struct {
		Params replayState `json:"params"`
	}
	json.Unmarshal(line, &m)
	return m.Params
}

// historyLine is the part of a replayed message legacyState and
// trimReplay look at.
type historyLine struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Update struct {
			SessionUpdate string `json:"sessionUpdate"`
		} `json:"update"`
	} `json:"params"`
}

func parseHistoryLine(line []byte) historyLine {
	var h historyLine
	json.Unmarshal(line, &h)
	return h
}

// updateKind returns line's sessionUpdate if it is one of kinds. The
// substring check skips parsing the (mostly large) other lines.
func updateKind(line []byte, kinds ...string) string {
	for _, k := range kinds {
		if bytes.Contains(line, []byte(k)) {
			kind := parseHistoryLine(line).Params.Update.SessionUpdate
			for _, k := range kinds {
				if kind == k {
					return kind
				}
			}
			return ""
		}
	}
	return ""
}

// legacyState infers the session state from history for multiplexers
// that don't report it: a turn is running if the last user message has no
// turn_complete after it. An old multiplexer replays an unanswered
// permission request last.
func legacyState(lines [][]byte) replayState {
	st := replayState{State: "idle", Legacy: true}
	lastUser, lastDone := -1, -1
	for i, line := range lines {
		switch updateKind(line, "user_message_chunk", "turn_complete", "available_commands_update") {
		case "user_message_chunk":
			lastUser = i
		case "turn_complete", "available_commands_update":
			lastDone = i
		}
	}
	if lastUser <= lastDone {
		return st
	}
	st.State = "working"
	if n := len(lines); n > 0 {
		if h := parseHistoryLine(lines[n-1]); h.Method == "session/request_permission" && h.ID != nil {
			st.State = "awaiting_input"
			st.Awaiting = []json.RawMessage{h.ID}
		}
	}
	return st
}

// trimReplay keeps the session header and as much recent history as fits
// in budget, starting at a user message where possible so turns aren't
// cut in half. Oversized tool calls are shrunk first. It returns the kept
// lines and how many history lines were left out.
func trimReplay(lines [][]byte, budget int) ([][]byte, int) {
	header := 0
	for header < len(lines) && isHeaderLine(lines[header]) {
		header++
	}
	history := make([][]byte, len(lines)-header)
	for i, line := range lines[header:] {
		history[i] = shrinkToolLine(line)
	}

	cut, size := len(history), 0
	for cut > 0 && size+len(history[cut-1]) <= budget {
		cut--
		size += len(history[cut])
	}
	if cut == len(history) && cut > 0 {
		cut-- // always show the latest message
	}
	if cut > 0 {
		for i := cut; i < len(history); i++ {
			if updateKind(history[i], "user_message_chunk") != "" {
				cut = i
				break
			}
		}
	}

	out := append([][]byte(nil), lines[:header]...)
	// Mode and command state still apply even if their messages are old.
	var mode, commands []byte
	for _, line := range history[:cut] {
		switch updateKind(line, "current_mode_update", "available_commands_update") {
		case "current_mode_update":
			mode = line
		case "available_commands_update":
			commands = line
		}
	}
	for _, l := range [][]byte{commands, mode} {
		if l != nil {
			out = append(out, l)
		}
	}
	return append(out, history[cut:]...), cut
}

// shrinkToolLine cuts long strings (file contents, command output) in an
// oversized tool_call or tool_call_update.
func shrinkToolLine(line []byte) []byte {
	if len(line) <= maxToolLine {
		return line
	}
	kind := parseHistoryLine(line).Params.Update.SessionUpdate
	if kind != "tool_call" && kind != "tool_call_update" {
		return line
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var v interface{}
	if dec.Decode(&v) != nil {
		return line
	}
	out, err := json.Marshal(shrinkStrings(v))
	if err != nil {
		return line
	}
	return out
}

func shrinkStrings(v interface{}) interface{} {
	switch x := v.(type) {
	case string:
		if len(x) <= maxToolString {
			return x
		}
		cut := maxToolString
		for cut > 0 && !utf8.RuneStart(x[cut]) {
			cut--
		}
		return x[:cut] + "\n… [" + formatBytes(len(x)-cut) + " more]"
	case map[string]interface{}:
		for k, e := range x {
			x[k] = shrinkStrings(e)
		}
	case []interface{}:
		for i, e := range x {
			x[i] = shrinkStrings(e)
		}
	}
	return v
}

func formatBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
