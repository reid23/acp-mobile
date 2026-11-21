package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/websocket"
)

//go:embed index.html
var indexHTML []byte

//go:embed katex
var katexFiles embed.FS

var validBufferName = regexp.MustCompile(`^[\w\s.\-@<>/()]+$`)

// --- Configuration ---

type config struct {
	ExtraPath []string `json:"extraPath"`
}

var appConfig config

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".acp-mobile", "config.json")
}

func loadConfig() config {
	var cfg config
	data, err := os.ReadFile(configPath())
	if err != nil {
		return cfg
	}
	json.Unmarshal(data, &cfg)
	return cfg
}

// command creates an exec.Cmd with extra PATH directories from config.
func command(name string, args ...string) *exec.Cmd {
	return commandContext(context.Background(), name, args...)
}

func commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	// exec.Command looks name up in our own PATH, not cmd.Env's, so the
	// extra directories have to be searched here too.
	path := name
	if !strings.Contains(name, "/") {
		for _, dir := range appConfig.ExtraPath {
			p := filepath.Join(dir, name)
			if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
				path = p
				break
			}
		}
	}
	cmd := exec.CommandContext(ctx, path, args...)
	if len(appConfig.ExtraPath) > 0 {
		env := os.Environ()
		extra := strings.Join(appConfig.ExtraPath, ":")
		found := false
		for i, e := range env {
			if strings.HasPrefix(e, "PATH=") {
				env[i] = "PATH=" + extra + ":" + e[5:]
				found = true
				break
			}
		}
		if !found {
			env = append(env, "PATH="+extra)
		}
		cmd.Env = env
	}
	return cmd
}

type tailscaleInfo struct {
	Hostname string
	IP       string
}

func tailscaleSelf() (tailscaleInfo, error) {
	out, err := command("tailscale", "status", "--self", "--json").Output()
	if err != nil {
		return tailscaleInfo{}, err
	}
	var status struct {
		Self struct {
			DNSName      string   `json:"DNSName"`
			TailscaleIPs []string `json:"TailscaleIPs"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		return tailscaleInfo{}, err
	}
	name := strings.TrimSuffix(status.Self.DNSName, ".")
	if name == "" {
		return tailscaleInfo{}, fmt.Errorf("no tailscale hostname")
	}
	var ip string
	for _, addr := range status.Self.TailscaleIPs {
		if strings.Contains(addr, ".") {
			ip = addr
			break
		}
	}
	return tailscaleInfo{Hostname: name, IP: ip}, nil
}

func authKeyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".acp-mobile", "authkey")
}

func loadOrCreateAuthKey() string {
	p := authKeyPath()
	data, err := os.ReadFile(p)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			return key
		}
	}
	// Generate new key
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("failed to generate authkey: %v", err)
	}
	key := hex.EncodeToString(b)
	os.MkdirAll(filepath.Dir(p), 0700)
	if err := os.WriteFile(p, []byte(key+"\n"), 0600); err != nil {
		log.Fatalf("failed to write authkey: %v", err)
	}
	log.Printf("generated new authkey at %s", p)
	return key
}

// Auth rate limiter: tracks failed attempts per IP
type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{attempts: make(map[string][]time.Time)}
}

// check returns true if the IP is rate-limited (too many recent failures).
func (rl *rateLimiter) check(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	window := time.Now().Add(-15 * time.Minute)
	attempts := rl.attempts[ip]
	// Prune old entries
	valid := attempts[:0]
	for _, t := range attempts {
		if t.After(window) {
			valid = append(valid, t)
		}
	}
	rl.attempts[ip] = valid
	return len(valid) >= 10 // 10 failures in 15 min = locked out
}

func (rl *rateLimiter) record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

var testMode bool

func main() {
	appConfig = loadConfig()

	port := "8090"
	for _, arg := range os.Args[1:] {
		if arg == "--test-mode" {
			testMode = true
		} else {
			port = arg
		}
	}

	authKey := loadOrCreateAuthKey()
	authRL := newRateLimiter()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		// Generate per-request CSP nonce
		nonceBytes := make([]byte, 16)
		rand.Read(nonceBytes)
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)

		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			fmt.Sprintf("default-src 'self'; script-src 'nonce-%s'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'", nonce))
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(bytes.Replace(indexHTML, []byte("__CSP_NONCE__"), []byte(nonce), 1))
	})

	mux.Handle("/ws", &websocket.Server{
		Handler: func(ws *websocket.Conn) {
			pid := ws.Request().URL.Query().Get("sock")
			if pid == "" {
				log.Printf("ws: missing sock param")
				ws.Close()
				return
			}
			if _, err := strconv.Atoi(pid); err != nil {
				log.Printf("ws: invalid sock param %q", pid)
				ws.Close()
				return
			}
			sockPath := findSocket(pid)
			if sockPath == "" {
				log.Printf("ws: no socket for pid %s", pid)
				websocket.Message.Send(ws, `{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Session not found","data":{"details":"No socket for pid `+pid+`"}}}`)
				ws.Close()
				return
			}
			bridgeWebSocket(ws, sockPath)
		},
		Handshake: func(config *websocket.Config, r *http.Request) error {
			origin := r.Header.Get("Origin")
			if origin == "" {
				if testMode {
					return nil
				}
				return fmt.Errorf("missing Origin header")
			}
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				return fmt.Errorf("origin %q not allowed", origin)
			}
			config.Origin, _ = websocket.Origin(config, r)
			return nil
		},
	})

	mux.Handle("/katex/", http.FileServerFS(katexFiles))
	mux.HandleFunc("/api/sessions", handleSessions)
	mux.HandleFunc("/api/spawn", handleSpawn)
	mux.HandleFunc("/api/kill", handleKill)
	mux.HandleFunc("/files/list", handleFileList)
	mux.HandleFunc("/files/read", handleFileRead)

	// CSRF protection via Sec-Fetch-Site headers
	cop := http.NewCrossOriginProtection()

	// Allowed hosts for DNS rebinding protection
	allowedHosts := map[string]bool{
		"127.0.0.1": true,
		"localhost": true,
	}
	// Extra hostnames served through a reverse proxy, e.g. a Cloudflare
	// tunnel: ACP_MOBILE_ALLOWED_HOSTS=agents.example.com,other.example.com
	var publicHost string
	for _, h := range strings.Split(os.Getenv("ACP_MOBILE_ALLOWED_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			allowedHosts[h] = true
			if publicHost == "" {
				publicHost = h
			}
		}
	}
	// Accept Cloudflare Access logins in place of the authkey:
	// ACP_MOBILE_CF_ACCESS_TEAM_DOMAIN=<team>.cloudflareaccess.com
	// ACP_MOBILE_CF_ACCESS_AUD=<application AUD tag>
	var cfAuth *cfAccess
	if team, aud := os.Getenv("ACP_MOBILE_CF_ACCESS_TEAM_DOMAIN"), os.Getenv("ACP_MOBILE_CF_ACCESS_AUD"); team != "" && aud != "" {
		cfAuth = newCFAccess(team, aud)
		log.Printf("acp-mobile: accepting Cloudflare Access tokens from %s", cfAuth.issuer)
	}
	ts, tsErr := tailscaleSelf()
	if tsErr == nil {
		allowedHosts[ts.Hostname] = true
		if ts.IP != "" {
			allowedHosts[ts.IP] = true
		}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DNS rebinding protection
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !allowedHosts[host] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Extract client IP for rate limiting
		clientIP := r.RemoteAddr
		if h, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = h
		}
		// Behind a local Cloudflare tunnel every request comes from loopback.
		if ip := net.ParseIP(clientIP); ip != nil && ip.IsLoopback() {
			if cf := r.Header.Get("Cf-Connecting-Ip"); cf != "" {
				clientIP = cf
			}
		}
		viaHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

		if cfAuth != nil && cfAuth.authorized(r) {
			mux.ServeHTTP(w, r)
			return
		}

		// Auth: if authkey query param is present and valid, set cookie and redirect
		if qk := r.URL.Query().Get("authkey"); qk != "" {
			if authRL.check(clientIP) {
				http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
				return
			}
			if subtle.ConstantTimeCompare([]byte(qk), []byte(authKey)) != 1 {
				authRL.record(clientIP)
				http.Error(w, "invalid authkey", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "authkey",
				Value:    authKey,
				Path:     "/",
				HttpOnly: true,
				Secure:   viaHTTPS,
				// Lax, not Strict: arriving from an SSO login (e.g. Cloudflare
				// Access) is a cross-site navigation, which Strict cookies skip.
				SameSite: http.SameSiteLaxMode,
			})
			// Redirect to strip authkey from URL
			q := r.URL.Query()
			q.Del("authkey")
			r.URL.RawQuery = q.Encode()
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
			return
		}

		// Auth: check cookie
		cookie, err := r.Cookie("authkey")
		if err != nil {
			// No key offered is not a guess; don't count it toward lockout.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(authKey)) != 1 {
			if authRL.check(clientIP) {
				http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
				return
			}
			authRL.record(clientIP)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		mux.ServeHTTP(w, r)
	})

	// Write link file
	link := fmt.Sprintf("http://127.0.0.1:%s?authkey=%s", port, authKey)
	if tsErr == nil {
		link = fmt.Sprintf("http://%s:%s?authkey=%s", ts.Hostname, port, authKey)
	}
	if publicHost != "" {
		link = fmt.Sprintf("https://%s/?authkey=%s", publicHost, authKey)
	}
	log.Printf("acp-mobile: %s", link)
	linkPath := filepath.Join(filepath.Dir(authKeyPath()), "link")
	os.WriteFile(linkPath, []byte(link+"\n"), 0600)

	wrapped := cop.Handler(handler)

	// Limit request body size (1MB)
	limited := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		wrapped.ServeHTTP(w, r)
	})

	// No ReadTimeout/WriteTimeout because they kill long-lived WebSocket
	// connections. ReadHeaderTimeout protects against slowloris without
	// affecting WebSockets (only applies during header read).
	makeServer := func(addr string) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           limited,
			IdleTimeout:       120 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	// Listen on localhost
	go func() {
		log.Fatal(makeServer(fmt.Sprintf("127.0.0.1:%s", port)).ListenAndServe())
	}()
	// Listen on Tailscale IP if available
	if tsErr == nil && ts.IP != "" {
		log.Printf("acp-mobile: also listening on %s:%s", ts.IP, port)
		log.Fatal(makeServer(fmt.Sprintf("%s:%s", ts.IP, port)).ListenAndServe())
	} else {
		select {}
	}
}

// --- Socket discovery ---

func socketDir() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "acp-multiplex")
}

type socketEntry struct {
	pid   int
	path  string
	mtime int64
}

func discoverSockets() []socketEntry {
	var socks []socketEntry
	seen := map[int]bool{}

	// New location: $TMPDIR/acp-multiplex/<pid>.sock
	dir := socketDir()
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".sock") {
				continue
			}
			pid, err := strconv.Atoi(strings.TrimSuffix(name, ".sock"))
			if err != nil {
				continue
			}
			if syscall.Kill(pid, 0) != nil {
				os.Remove(filepath.Join(dir, name))
				continue
			}
			seen[pid] = true
			var mt int64
			if info, err := e.Info(); err == nil {
				mt = info.ModTime().Unix()
			}
			socks = append(socks, socketEntry{pid, filepath.Join(dir, name), mt})
		}
	}

	// Legacy: $TMPDIR/acp-multiplex-<pid>.sock
	tmpdir := os.TempDir()
	if entries, err := os.ReadDir(tmpdir); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, "acp-multiplex-") || !strings.HasSuffix(name, ".sock") {
				continue
			}
			pidStr := strings.TrimSuffix(strings.TrimPrefix(name, "acp-multiplex-"), ".sock")
			pid, err := strconv.Atoi(pidStr)
			if err != nil || seen[pid] {
				continue
			}
			if syscall.Kill(pid, 0) != nil {
				os.Remove(filepath.Join(tmpdir, name))
				continue
			}
			var mt int64
			if info, err := e.Info(); err == nil {
				mt = info.ModTime().Unix()
			}
			socks = append(socks, socketEntry{pid, filepath.Join(tmpdir, name), mt})
		}
	}

	return socks
}

func findSocket(pidStr string) string {
	p := filepath.Join(socketDir(), pidStr+".sock")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	p = filepath.Join(os.TempDir(), "acp-multiplex-"+pidStr+".sock")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// --- Session probing ---

type sessionInfo struct {
	Pid          int    `json:"pid"`
	SessionID    string `json:"sessionId,omitempty"`
	Title        string `json:"title,omitempty"`
	Cwd          string `json:"cwd,omitempty"`
	Project      string `json:"project,omitempty"`
	BufferName   string `json:"bufferName,omitempty"`
	LastActivity int64  `json:"lastActivity"` // unix timestamp
	// idle, working or awaiting_input; empty if the probe didn't finish.
	State      string `json:"state,omitempty"`
	StateSince int64  `json:"stateSince,omitempty"`
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	socks := discoverSockets()

	type result struct {
		info sessionInfo
		ok   bool
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	results := make([]result, len(socks))

	for i, s := range socks {
		idx := i
		sock := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan struct{})
			var info sessionInfo
			go func() {
				info = probeSocket(sock.path, sock.pid, sock.mtime)
				close(done)
			}()
			select {
			case <-done:
				info.LastActivity = sock.mtime
				results[idx] = result{info: info, ok: true}
			case <-ctx.Done():
				// Timed out — return partial info
				results[idx] = result{
					info: sessionInfo{Pid: sock.pid, LastActivity: sock.mtime},
					ok:   true,
				}
			}
		}()
	}
	wg.Wait()

	var sessions []sessionInfo
	for _, r := range results {
		if r.ok {
			sessions = append(sessions, r.info)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"sessions": sessions})
}

func handleSpawn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Cwd  string `json:"cwd"`
		Name string `json:"name"`
		Task string `json:"task"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Cwd == "" {
		http.Error(w, "name and cwd are required", http.StatusBadRequest)
		return
	}

	args := []string{req.Name, req.Cwd}
	if req.Task != "" {
		args = append(args, req.Task)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := commandContext(ctx, "agent-shell-spawn", args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out waiting for Emacs")
	}
	if err != nil {
		log.Printf("spawn: %v: %s", err, out)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		BufferName string `json:"bufferName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.BufferName == "" {
		http.Error(w, "bufferName is required", http.StatusBadRequest)
		return
	}

	// Validate buffer name: only allow characters that appear in agent-shell names
	// (e.g. "Claude Code Agent @ myproject<2>")
	if !validBufferName.MatchString(req.BufferName) {
		http.Error(w, "invalid buffer name", http.StatusBadRequest)
		return
	}

	// Escape for elisp string
	escaped := strings.ReplaceAll(req.BufferName, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	expr := fmt.Sprintf(`(meta-agent-shell-close-session "%s")`, escaped)

	out, err := command("emacsclient", "--eval", expr).CombinedOutput()
	if err != nil {
		log.Printf("kill: %v: %s", err, out)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))})
		return
	}

	result := strings.TrimSpace(string(out))
	if result == "nil" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "session not found or already closed"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// Older multiplexers have to replay their whole history for us to infer
// the session state, so those probes are cached until the socket's mtime
// (touched on agent activity) changes.
var legacyProbes = struct {
	sync.Mutex
	m map[int]legacyProbe
}{m: map[int]legacyProbe{}}

type legacyProbe struct {
	mtime int64
	at    time.Time
	info  sessionInfo
}

func probeSocket(sockPath string, pid int, mtime int64) sessionInfo {
	legacyProbes.Lock()
	cached, ok := legacyProbes.m[pid]
	legacyProbes.Unlock()
	if ok && cached.mtime == mtime && time.Since(cached.at) < time.Minute {
		return cached.info
	}

	info := sessionInfo{Pid: pid}

	info.Cwd = processCwd(pid)
	if info.Cwd != "" {
		info.Project = filepath.Base(info.Cwd)
	}

	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		return info
	}
	defer conn.Close()

	lines, st, err := readReplay(newLineReader(conn), 2*time.Second, true)
	if err == nil {
		info.State = st.State
		info.StateSince = st.Since
	}

	for _, line := range lines {
		var msg struct {
			Result json.RawMessage `json:"result"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(line, &msg) != nil {
			continue
		}

		// Check for acp-multiplex/meta notification
		if msg.Method == "acp-multiplex/meta" && msg.Params != nil {
			var meta struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(msg.Params, &meta) == nil && meta.Name != "" {
				info.BufferName = meta.Name
			}
			continue
		}

		if msg.Method != "" {
			break // past the header
		}
		if msg.Result == nil {
			continue
		}

		var res struct {
			AgentInfo *struct {
				Title string `json:"title"`
				Name  string `json:"name"`
			} `json:"agentInfo"`
			SessionID string `json:"sessionId"`
			Cwd       string `json:"cwd"`
		}
		if json.Unmarshal(msg.Result, &res) != nil {
			continue
		}

		if res.AgentInfo != nil {
			info.Title = res.AgentInfo.Title
			if info.Title == "" {
				info.Title = res.AgentInfo.Name
			}
		}
		if res.SessionID != "" && info.SessionID == "" {
			info.SessionID = res.SessionID
		}
		if res.Cwd != "" {
			info.Cwd = res.Cwd
			info.Project = filepath.Base(info.Cwd)
		}
	}

	if st.Legacy && err == nil {
		legacyProbes.Lock()
		legacyProbes.m[pid] = legacyProbe{mtime: mtime, at: time.Now(), info: info}
		for p := range legacyProbes.m {
			if syscall.Kill(p, 0) != nil {
				delete(legacyProbes.m, p)
			}
		}
		legacyProbes.Unlock()
	}
	return info
}

func processCwd(pid int) string {
	// Try /proc/<pid>/cwd first (Linux)
	if target, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		return target
	}
	// Fall back to lsof (macOS)
	out, err := command("lsof", "-a", "-d", "cwd", "-p", strconv.Itoa(pid), "-Fn").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "n/") {
			return line[1:]
		}
	}
	return ""
}

// --- Reverse call handlers ---

// handleReverseCall checks if a JSON line from the socket is a reverse call
// (fs/read_text_file, fs/write_text_file) that we can handle locally.
// Returns the JSON-RPC response to send back, or nil if not a handled method.
func handleReverseCall(line []byte) []byte {
	var env struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal(line, &env) != nil || env.Method == "" || env.ID == nil {
		return nil
	}

	switch env.Method {
	case "fs/read_text_file":
		return handleFsRead(env.ID, env.Params)
	case "fs/write_text_file":
		return handleFsWrite(env.ID, env.Params)
	default:
		return nil
	}
}

func handleFsRead(id json.RawMessage, params json.RawMessage) []byte {
	var p struct {
		Path  string `json:"path"`
		Line  *int   `json:"line"`
		Limit *int   `json:"limit"`
	}
	if json.Unmarshal(params, &p) != nil || p.Path == "" {
		return jsonRPCError(id, -32602, "invalid params")
	}

	data, err := os.ReadFile(p.Path)
	if err != nil {
		return jsonRPCError(id, -32000, err.Error())
	}

	content := string(data)

	// Handle line/limit offset (1-based line numbers)
	if p.Line != nil || p.Limit != nil {
		lines := strings.Split(content, "\n")
		start := 0
		if p.Line != nil && *p.Line > 1 {
			start = *p.Line - 1
		}
		if start > len(lines) {
			start = len(lines)
		}
		lines = lines[start:]
		if p.Limit != nil && *p.Limit < len(lines) {
			lines = lines[:*p.Limit]
		}
		content = strings.Join(lines, "\n")
	}

	resp, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  map[string]string{"content": content},
	})
	return resp
}

func handleFsWrite(id json.RawMessage, params json.RawMessage) []byte {
	var p struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if json.Unmarshal(params, &p) != nil || p.Path == "" {
		return jsonRPCError(id, -32602, "invalid params")
	}

	if err := os.WriteFile(p.Path, []byte(p.Content), 0644); err != nil {
		return jsonRPCError(id, -32000, err.Error())
	}

	resp, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  map[string]interface{}{},
	})
	return resp
}

func jsonRPCError(id json.RawMessage, code int, message string) []byte {
	resp, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]interface{}{"code": code, "message": message},
	})
	return resp
}

// --- WebSocket bridge ---

const (
	// The page pings every 25s; a connection silent for longer than this
	// is dead (e.g. a phone that went to sleep) and is dropped.
	wsIdleTimeout = 90 * time.Second
	// A write stuck this long means the browser stopped reading.
	wsWriteTimeout = 30 * time.Second
	// Newer acp-multiplex builds mark the end of the replay; this only
	// guards against one that never finishes.
	replayTimeout = 30 * time.Second
)

// bridgeWebSocket connects to the proxy socket and bridges to the browser.
// It sends the (trimmed) replay followed by acp-mobile/replay_end, which
// carries the session state, then forwards live traffic.
func bridgeWebSocket(ws *websocket.Conn, sockPath string) {
	var wmu sync.Mutex
	send := func(msg []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		ws.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
		return websocket.Message.Send(ws, string(msg))
	}
	sendError := func(message string, err error) {
		b, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0", "id": nil,
			"error": map[string]interface{}{
				"code": -32000, "message": message,
				"data": map[string]string{"details": err.Error()},
			},
		})
		send(b)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		log.Printf("ws: connect to %s: %v", sockPath, err)
		sendError("Connection failed", err)
		ws.Close()
		return
	}
	defer conn.Close()
	var cmu sync.Mutex
	writeSock := func(line []byte) error {
		cmu.Lock()
		defer cmu.Unlock()
		_, err := conn.Write(append(line[:len(line):len(line)], '\n'))
		return err
	}

	r := newLineReader(conn)
	lines, st, err := readReplay(r, replayTimeout, false)
	if err != nil && !isTimeout(err) {
		log.Printf("ws: replay from %s: %v", sockPath, err)
		sendError("Session ended", err)
		ws.Close()
		return
	}
	total := len(lines)
	omitted := 0
	if ws.Request().URL.Query().Get("history") != "all" {
		lines, omitted = trimReplay(lines, replayBudget)
	}
	for _, line := range lines {
		if err := send(line); err != nil {
			log.Printf("ws: send replay: %v", err)
			ws.Close()
			return
		}
	}
	end, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "acp-mobile/replay_end",
		"params": map[string]interface{}{
			"state":    st.State,
			"since":    st.Since,
			"awaiting": st.Awaiting,
			"legacy":   st.Legacy,
			"omitted":  omitted,
		},
	})
	if err := send(end); err != nil {
		ws.Close()
		return
	}
	log.Printf("ws: replayed %d of %d messages, state %s", len(lines), total, st.State)

	// Bridge live traffic
	var once sync.Once
	closeAll := func() {
		ws.Close()
		conn.Close()
	}

	go func() {
		defer once.Do(closeAll)
		for {
			ws.SetReadDeadline(time.Now().Add(wsIdleTimeout))
			var msg string
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				if err != io.EOF {
					log.Printf("ws recv: %v", err)
				}
				return
			}
			if strings.Contains(msg, `"acp-mobile/ping"`) && lineMethod([]byte(msg)) == "acp-mobile/ping" {
				if send([]byte(`{"jsonrpc":"2.0","method":"acp-mobile/pong"}`)) != nil {
					return
				}
				continue
			}
			if err := writeSock([]byte(msg)); err != nil {
				log.Printf("ws: write to socket: %v", err)
				return
			}
		}
	}()

	defer once.Do(closeAll)
	for {
		line, err := r.next(time.Time{})
		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				log.Printf("ws sock read: %v", err)
			}
			return
		}
		// Reverse calls we can answer locally go straight back.
		if resp := handleReverseCall(line); resp != nil {
			writeSock(resp)
			continue
		}
		if err := send(line); err != nil {
			log.Printf("ws send: %v", err)
			return
		}
	}
}

// --- File browser ---

// allowedRoots returns the cwd of each active session.
func allowedRoots() []string {
	socks := discoverSockets()
	seen := map[string]bool{}
	var roots []string
	for _, s := range socks {
		cwd := processCwd(s.pid)
		if cwd != "" && !seen[cwd] {
			seen[cwd] = true
			roots = append(roots, cwd)
		}
	}
	return roots
}

// isUnderRoots checks if absPath is under one of the allowed roots.
// Resolves symlinks to prevent traversal via symlinked directories.
func isUnderRoots(absPath string, roots []string) bool {
	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return false
	}
	for _, root := range roots {
		rootResolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		rootResolved = filepath.Clean(rootResolved) + string(filepath.Separator)
		if strings.HasPrefix(resolved+string(filepath.Separator), rootResolved) {
			return true
		}
	}
	return false
}

type fileEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size,omitempty"`
}

func handleFileList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path       string `json:"path"`
		ShowHidden bool   `json:"showHidden"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	dirPath := req.Path
	if dirPath == "" {
		dirPath = "."
	}

	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	if !isUnderRoots(absPath, allowedRoots()) {
		http.Error(w, "path not allowed", http.StatusForbidden)
		return
	}

	entries, err := os.ReadDir(absPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	showHidden := req.ShowHidden
	var files []fileEntry
	for _, e := range entries {
		name := e.Name()
		if !showHidden && strings.HasPrefix(name, ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		fe := fileEntry{Name: name, IsDir: e.IsDir()}
		if !e.IsDir() {
			fe.Size = info.Size()
		}
		files = append(files, fe)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"path":  absPath,
		"files": files,
	})
}

func handleFileRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	filePath := req.Path
	if filePath == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	if !isUnderRoots(absPath, allowedRoots()) {
		http.Error(w, "path not allowed", http.StatusForbidden)
		return
	}

	info, err := os.Stat(absPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if info.IsDir() {
		http.Error(w, "path is a directory", http.StatusBadRequest)
		return
	}
	if info.Size() > 1024*1024 {
		http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
		return
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"path":    absPath,
		"content": string(data),
	})
}
