package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func update(kind string, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":%q%s}}}`, kind, extra)
}

const (
	testMeta  = `{"jsonrpc":"2.0","method":"acp-multiplex/meta","params":{"name":"Cursor Agent @ proj"}}`
	testInit  = `{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentInfo":{"name":"cursor","title":"Cursor"}}}`
	testNew   = `{"jsonrpc":"2.0","id":0,"result":{"sessionId":"s1"}}`
	testBegin = `{"jsonrpc":"2.0","method":"acp-multiplex/replay_begin","params":{"state":"working","since":100,"awaiting":[]}}`
	testEnd   = `{"jsonrpc":"2.0","method":"acp-multiplex/replay_end","params":{"state":"working","since":100,"awaiting":[]}}`
)

// pipeReader returns a lineReader over a pipe fed with lines; the
// writer side stays open afterwards, like a live multiplexer socket.
func pipeReader(t *testing.T, lines ...string) (*lineReader, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		for _, l := range lines {
			server.Write([]byte(l + "\n"))
		}
	}()
	return newLineReader(client), server
}

func TestReadReplayUsesMarkers(t *testing.T) {
	r, server := pipeReader(t, testBegin, testMeta, testInit, testNew,
		update("user_message_chunk", `"content":{"type":"text","text":"hi"}`), testEnd)

	start := time.Now()
	lines, st, err := readReplay(r, 5*time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 4 {
		t.Fatalf("expected 4 history lines, got %d", len(lines))
	}
	if st.State != "working" || st.Since != 100 || st.Legacy {
		t.Errorf("unexpected state %+v", st)
	}
	if time.Since(start) > legacyReplayIdle {
		t.Errorf("marked replay should not wait for the socket to go quiet")
	}

	// Live traffic after the marker is left for the bridge.
	go server.Write([]byte(update("agent_message_chunk", "") + "\n"))
	line, err := r.next(time.Now().Add(time.Second))
	if err != nil || !strings.Contains(string(line), "agent_message_chunk") {
		t.Fatalf("expected live line after replay, got %s, %v", line, err)
	}
}

func TestReadReplayHeaderOnly(t *testing.T) {
	r, _ := pipeReader(t, testBegin, testMeta, testInit, testNew,
		update("user_message_chunk", ""), update("tool_call", `"toolCallId":"t1"`), testEnd)
	lines, st, err := readReplay(r, 5*time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || st.State != "working" {
		t.Fatalf("expected the 3 header lines and state, got %d lines, %+v", len(lines), st)
	}
}

func TestReadReplayLegacy(t *testing.T) {
	r, _ := pipeReader(t, testMeta, testInit, testNew,
		update("user_message_chunk", ""), update("turn_complete", ""))
	lines, st, err := readReplay(r, 5*time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 5 || st.State != "idle" || !st.Legacy {
		t.Fatalf("got %d lines, %+v", len(lines), st)
	}
}

func lines(ss ...string) [][]byte {
	var out [][]byte
	for _, s := range ss {
		out = append(out, []byte(s))
	}
	return out
}

func TestLegacyState(t *testing.T) {
	perm := `{"jsonrpc":"2.0","id":42,"method":"session/request_permission","params":{"sessionId":"s1"}}`
	cases := []struct {
		name  string
		lines [][]byte
		want  string
	}{
		{"empty", nil, "idle"},
		{"finished turn", lines(update("user_message_chunk", ""), update("tool_call", ""), update("turn_complete", "")), "idle"},
		{"running turn", lines(update("turn_complete", ""), update("user_message_chunk", ""), update("tool_call", "")), "working"},
		{"pending permission", lines(update("user_message_chunk", ""), perm), "awaiting_input"},
		// History streamed by session/load has no turn_complete, but the
		// agent sends available commands once the load is done.
		{"resumed session", lines(update("user_message_chunk", ""), update("agent_message_chunk", ""), update("available_commands_update", "")), "idle"},
		// Answered permissions stay in history; only the turn state matters.
		{"answered permission", lines(update("user_message_chunk", ""), perm, update("turn_complete", "")), "idle"},
	}
	for _, c := range cases {
		if got := legacyState(c.lines).State; got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if st := legacyState(lines(update("user_message_chunk", ""), perm)); len(st.Awaiting) != 1 || string(st.Awaiting[0]) != "42" {
		t.Errorf("expected awaiting [42], got %s", st.Awaiting)
	}
}

func TestTrimReplay(t *testing.T) {
	filler := strings.Repeat("x", 1000)
	in := lines(testMeta, testInit, testNew,
		update("current_mode_update", `"currentModeId":"plan"`))
	for turn := 0; turn < 20; turn++ {
		in = append(in, []byte(update("user_message_chunk", fmt.Sprintf(`"content":{"type":"text","text":"turn %d"}`, turn))))
		for i := 0; i < 5; i++ {
			in = append(in, []byte(update("agent_message_chunk", fmt.Sprintf(`"content":{"type":"text","text":%q}`, filler))))
		}
	}

	out, omitted := trimReplay(in, 20_000)
	size := 0
	for _, l := range out[3:] {
		size += len(l)
	}
	if size > 20_000 {
		t.Errorf("kept %d bytes of history, budget 20000", size)
	}
	for i, want := range []string{testMeta, testInit, testNew} {
		if string(out[i]) != want {
			t.Fatalf("header line %d not kept: %s", i, out[i])
		}
	}
	if !strings.Contains(string(out[3]), `"currentModeId":"plan"`) {
		t.Errorf("mode from trimmed history should be kept, got %s", out[3])
	}
	if !strings.Contains(string(out[4]), "user_message_chunk") {
		t.Errorf("kept history should start at a user message, got %.80s", out[4])
	}
	if !strings.Contains(string(out[len(out)-1]), filler) || !strings.Contains(string(out[len(out)-6]), "turn 19") {
		t.Errorf("latest turn should be kept intact")
	}
	if omitted+len(out)-4 != len(in)-3 {
		t.Errorf("omitted %d + kept %d != history %d", omitted, len(out)-4, len(in)-3)
	}

	// Within budget nothing is dropped.
	if out, omitted := trimReplay(in, 1<<30); omitted != 0 || len(out) != len(in) {
		t.Errorf("expected everything kept, got %d of %d (omitted %d)", len(out), len(in), omitted)
	}
}

func TestShrinkToolLine(t *testing.T) {
	big := strings.Repeat("é", 20_000) // multi-byte, to check cuts land on rune boundaries
	line := []byte(update("tool_call_update", fmt.Sprintf(`"toolCallId":"t1","status":"completed","content":[{"type":"content","content":{"type":"text","text":%q}}],"rawOutput":{"exitCode":0}`, big)))
	out := shrinkToolLine(line)
	if len(out) > maxToolLine {
		t.Fatalf("shrunk line is %d bytes", len(out))
	}
	var m struct {
		Params struct {
			Update struct {
				ToolCallID string `json:"toolCallId"`
				Status     string `json:"status"`
				Content    []struct {
					Content struct{ Text string } `json:"content"`
				} `json:"content"`
				RawOutput struct {
					ExitCode json.Number `json:"exitCode"`
				} `json:"rawOutput"`
			} `json:"update"`
		} `json:"params"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	u := m.Params.Update
	if u.ToolCallID != "t1" || u.Status != "completed" || u.RawOutput.ExitCode != "0" {
		t.Errorf("fields lost: %+v", u)
	}
	if text := u.Content[0].Content.Text; !strings.HasPrefix(text, "éé") || !strings.Contains(text, "more]") || strings.ContainsRune(text, '\uFFFD') {
		t.Errorf("unexpected shrunk text: %.40q…", text)
	}

	agent := []byte(update("agent_message_chunk", fmt.Sprintf(`"content":{"type":"text","text":%q}`, big)))
	if string(shrinkToolLine(agent)) != string(agent) {
		t.Error("agent messages must not be shrunk")
	}
}

// TestBridgeReplayEndAndPing runs the WebSocket bridge against a fake
// multiplexer socket.
func TestBridgeReplayEndAndPing(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "1.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fromBrowser := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for _, l := range []string{testBegin, testMeta, testInit, testNew, update("user_message_chunk", ""), testEnd} {
			conn.Write([]byte(l + "\n"))
		}
		r := newLineReader(conn)
		line, err := r.next(time.Now().Add(5 * time.Second))
		if err != nil {
			return
		}
		fromBrowser <- string(line)
		conn.Write([]byte(update("agent_message_chunk", `"content":{"type":"text","text":"live"}`) + "\n"))
		time.Sleep(time.Second)
	}()

	mux := http.NewServeMux()
	mux.Handle("/ws", &websocket.Server{
		Handler:   func(ws *websocket.Conn) { bridgeWebSocket(ws, sockPath) },
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ws, err := websocket.Dial(strings.Replace(srv.URL, "http://", "ws://", 1)+"/ws?sock=1", "", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	recv := func() string {
		t.Helper()
		var msg string
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			t.Fatalf("receive: %v", err)
		}
		return msg
	}

	var got []string
	for {
		msg := recv()
		if lineMethod([]byte(msg)) == "acp-mobile/replay_end" {
			st := parseState([]byte(msg))
			if st.State != "working" || st.Legacy {
				t.Errorf("unexpected replay_end state: %s", msg)
			}
			break
		}
		got = append(got, msg)
	}
	if len(got) != 4 || got[0] != testMeta {
		t.Fatalf("expected meta, init, new and the user message in order, got %q", got)
	}

	websocket.Message.Send(ws, `{"jsonrpc":"2.0","method":"acp-mobile/ping"}`)
	if msg := recv(); lineMethod([]byte(msg)) != "acp-mobile/pong" {
		t.Fatalf("expected pong, got %s", msg)
	}

	prompt := `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s1","prompt":[]}}`
	websocket.Message.Send(ws, prompt)
	select {
	case line := <-fromBrowser:
		if line != prompt {
			t.Errorf("socket got %s", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prompt never reached the socket (pings must not be forwarded either)")
	}
	if msg := recv(); !strings.Contains(msg, `"live"`) {
		t.Errorf("expected live update, got %s", msg)
	}
}
