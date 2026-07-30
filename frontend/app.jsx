/*
 * app.jsx - NOC Portal frontend.
 * Outer portal access is handled by /login and the NOC session cookie.
 * Per-switch lock and unlock remain inside the dashboard.
 */

const { useState, useEffect, useCallback, useMemo } = React;

// ────────────────────────────────────────────────────────────────────
// Config + localStorage helpers
// ────────────────────────────────────────────────────────────────────
// API base URL.
//
// Every call site below already uses an absolute "/api/..." path, so the
// default base is an EMPTY string — meaning "same origin as this page".
// The browser therefore requests e.g. http://<host>:5173/api/switches, and
// Nginx (see nginx.conf) proxies /api to the backend container.
//
// This is what fixes the "Failed to fetch" error for good:
//   • no separate :18000 cross-origin request  → no CORS preflight to fail
//   • same scheme as the page (http OR https)  → no mixed-content blocking
//
// Escape hatch: to point the UI at a backend on another host/port, set
//   window.NOC_API_BASE = "http://1.2.3.4:18000"
// before this script loads (e.g. a <script> in index.html) and it wins.
const API = (typeof window !== "undefined" && window.NOC_API_BASE)
  ? window.NOC_API_BASE
  : "";

const LS_TOKENS    = "noc_admin_tokens";
const LS_USERNAMES = "noc_admin_usernames";

const loadJson = (k, fallback) => {
  try { return JSON.parse(localStorage.getItem(k)) || fallback; }
  catch { return fallback; }
};
const saveJson = (k, v) => localStorage.setItem(k, JSON.stringify(v));

const getTokens    = () => loadJson(LS_TOKENS, {});
const getUsernames = () => loadJson(LS_USERNAMES, {});

const setTokenFor = (switchName, token, username) => {
  const t = getTokens(); const u = getUsernames();
  t[switchName] = token; u[switchName] = username;
  saveJson(LS_TOKENS, t); saveJson(LS_USERNAMES, u);
};
const removeTokenFor = (switchName) => {
  const t = getTokens(); const u = getUsernames();
  delete t[switchName]; delete u[switchName];
  saveJson(LS_TOKENS, t); saveJson(LS_USERNAMES, u);
};
const clearAllTokens = () => {
  localStorage.removeItem(LS_TOKENS);
  localStorage.removeItem(LS_USERNAMES);
};

// ────────────────────────────────────────────────────────────────────
// API client
// ────────────────────────────────────────────────────────────────────
async function api(path, opts = {}, switchName = null) {
  const tokens = getTokens();
  const token = switchName ? tokens[switchName] : Object.values(tokens)[0];
  const headers = Object.assign({}, opts.headers || {});
  if (token) headers["X-Admin-Token"] = token;
  // FormData must NOT get an explicit Content-Type: the browser has to set it
  // itself so it can append the multipart boundary. Forcing application/json
  // here (as this did) makes every file upload fail to parse server-side.
  const isForm = (typeof FormData !== "undefined") && (opts.body instanceof FormData);
  if (opts.body && !isForm && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  let r;
  try {
    r = await fetch(API + path, Object.assign({}, opts, { headers }));
  } catch (netErr) {
    // True network-level failure (server unreachable, DNS, CORS block).
    const e = new Error(
      "Cannot reach the server. Is the backend running and is the /api proxy " +
      "active? (" + (netErr.message || "network error") + ")"
    );
    e.status = 0;
    throw e;
  }

  // Read the body as text first so we can detect non-JSON responses (an HTML
  // error page from nginx, an empty 204, etc.) and give a clear message instead
  // of the cryptic 'Unexpected token <' JSON parse error.
  const raw = await r.text();
  const ctype = r.headers.get("content-type") || "";
  let data = null;
  if (raw && ctype.indexOf("application/json") !== -1) {
    try { data = JSON.parse(raw); } catch { data = null; }
  } else if (raw && raw.trim()[0] === "{") {
    // Some servers omit the header but still send JSON — try anyway.
    try { data = JSON.parse(raw); } catch { data = null; }
  }

  // Got HTML where JSON was expected → almost always the /api request was NOT
  // proxied to the backend and nginx returned index.html (the SPA fallback).
  // This is the "Unexpected token '<'" situation, surfaced clearly.
  if (data === null && raw && raw.trim()[0] === "<") {
    const e = new Error(
      "The API returned an HTML page instead of data — the /api proxy isn't " +
      "active. Rebuild the frontend container so nginx.conf takes effect: " +
      "`docker compose up -d --build frontend` (and hard-refresh the page)."
    );
    e.status = r.status;
    throw e;
  }

  if (!r.ok) {
    // 401 means the session token has expired (8-hour TTL) or the server
    // restarted (sessions live in RAM only). Auto-clear the stale token so
    // the UI falls back to the login screen instead of looping on errors.
    if (r.status === 401 && switchName) {
      removeTokenFor(switchName);
      window.dispatchEvent(new Event("storage")); // sync loggedIn state
    }
    const msg = (data && data.detail) || r.statusText || `HTTP ${r.status}`;
    const err = new Error(msg);
    err.status = r.status;
    throw err;
  }
  return data;  // may be null for an empty 204 — callers handle that
}

async function loginRequest(username, password, scope) {
  let r;
  try {
    r = await fetch(API + "/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username, password: password, scope: scope }),
    });
  } catch (netErr) {
    throw new Error(
      "Cannot reach the server. Is the backend running and the /api proxy active? " +
      "(" + (netErr.message || "network error") + ")"
    );
  }
  const raw = await r.text();
  if (raw && raw.trim()[0] === "<") {
    throw new Error(
      "Login endpoint returned an HTML page — the /api proxy isn't active. " +
      "Rebuild the frontend container (`docker compose up -d --build frontend`) " +
      "and hard-refresh."
    );
  }
  let data = null;
  try { data = JSON.parse(raw); } catch { data = null; }
  if (!r.ok) throw new Error((data && data.detail) || "login failed");
  return data;
}

// ────────────────────────────────────────────────────────────────────
// Small utilities
// ────────────────────────────────────────────────────────────────────
const fmt = (n) => (n === null || n === undefined) ? "—" : Number(n).toLocaleString();

// Compact units for very large packet counters:
//   15,650,167,488 -> "15.65B". Exact value stays available in a tooltip.
const fmtNum = (n) => {
  if (n === null || n === undefined) return "—";
  n = Number(n);
  const a = Math.abs(n);
  if (a < 1000) return n.toLocaleString();
  const units = [[1e12,"T"],[1e9,"B"],[1e6,"M"],[1e3,"K"]];
  for (let i = 0; i < units.length; i++) {
    const v = units[i][0], s = units[i][1];
    if (a >= v) { const x = n / v; return (Math.abs(x) >= 100 ? x.toFixed(0) : x.toFixed(2)) + s; }
  }
  return n.toLocaleString();
};

// Byte units (1024-based): 10,050,785,598,692 -> "9.14 TB".
const fmtBytes = (n) => {
  if (n === null || n === undefined) return "—";
  n = Number(n);
  if (n === 0) return "0 B";
  const a = Math.abs(n);
  const units = ["B","KB","MB","GB","TB","PB","EB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(a) / Math.log(1024)));
  const x = n / Math.pow(1024, i);
  const d = i === 0 ? 0 : (Math.abs(x) >= 100 ? 1 : 2);
  return x.toFixed(d) + " " + units[i];
};

// Humanize a window of seconds: 58 -> "58s", 900 -> "15m", 3658 -> "1h 0m".
const fmtDur = (s) => {
  if (s === null || s === undefined) return "—";
  s = Math.round(Number(s));
  if (s < 60) return s + "s";
  if (s < 3600) { const m = Math.floor(s/60), ss = s%60; return ss ? (m+"m "+ss+"s") : (m+"m"); }
  if (s < 86400) { const h = Math.floor(s/3600), m = Math.floor((s%3600)/60); return h+"h "+m+"m"; }
  const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600); return d+"d "+h+"h";
};

// Mode-aware number formatting for the port-stats table, driven by the Units
// dropdown. `mode`: "auto" (dynamic 15.65B / 9.14 TB), "exact" (full grouped
// number), or a forced tier K/M/B/T. Counts use decimal tiers; bytes use the
// binary equivalent (K->KB, M->MB, B->GB, T->TB) so one dropdown drives both.
const UNIT_DIV = {
  count: { K: [1e3,"K"], M: [1e6,"M"], B: [1e9,"B"], T: [1e12,"T"] },
  bytes: { K: [1024,"KB"], M: [1024**2,"MB"], B: [1024**3,"GB"], T: [1024**4,"TB"] },
};
const fmtUnit = (n, mode, isBytes) => {
  if (n === null || n === undefined) return "—";
  n = Number(n);
  if (mode === "exact") return n.toLocaleString();
  if (mode === "auto" || !UNIT_DIV[isBytes ? "bytes" : "count"][mode]) {
    return isBytes ? fmtBytes(n) : fmtNum(n);
  }
  const [div, label] = UNIT_DIV[isBytes ? "bytes" : "count"][mode];
  const x = n / div;
  const dec = Math.abs(x) >= 100 ? (isBytes ? 1 : 0) : 2;
  return x.toFixed(dec) + (isBytes ? " " : "") + label;
};

// Format any timestamp explicitly in India Standard Time, so the dashboard
// shows IST even if the viewer's browser/OS is set to another timezone.
const istTime = (iso) => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: true,
    });
  } catch (_) {
    return new Date(iso).toLocaleString();
  }
};

const ago = (iso) => {
  if (!iso) return "—";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 0)     return "just now";   // clock skew guard
  if (s < 60)   return s + "s ago";
  if (s < 3600) return Math.round(s/60) + "m ago";
  if (s < 86400) return Math.round(s/3600) + "h ago";
  return Math.round(s/86400) + "d ago";
};

const cls = function () {
  return Array.prototype.slice.call(arguments).filter(Boolean).join(" ");
};

// Lightweight, safe markdown -> HTML for chat answers. Handles the few things
// the model emits (bold, inline code, simple bullets, paragraphs) and escapes
// everything else so it stays readable instead of showing literal ** and #.
function renderChat(text) {
  if (!text) return { __html: "" };
  // 1. Escape HTML special chars first (safety).
  let s = text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  // 2. Inline code `like this`
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  // 3. Bold **like this** (and strip stray standalone ** )
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // 4. Strip leading markdown heading hashes ("### Title" -> "Title")
  s = s.replace(/^#{1,6}\s*/gm, "");
  // 5. Build paragraphs / lists line by line.
  const lines = s.split(/\r?\n/);
  let html = "";
  let inList = false;
  lines.forEach(function(raw) {
    const line = raw.trim();
    const isBullet = /^[-*]\s+/.test(line);
    if (isBullet) {
      if (!inList) { html += "<ul>"; inList = true; }
      html += "<li>" + line.replace(/^[-*]\s+/, "") + "</li>";
    } else {
      if (inList) { html += "</ul>"; inList = false; }
      if (line.length === 0) { html += ""; }
      else { html += "<p>" + line + "</p>"; }
    }
  });
  if (inList) html += "</ul>";
  return { __html: html };
}

// ────────────────────────────────────────────────────────────────────
// ────────────────────────────────────────────────────────────────────


// ────────────────────────────────────────────────────────────────────
// UnlockPrompt — inline dialog for a previously locked switch
// ────────────────────────────────────────────────────────────────────
function UnlockPrompt(props) {
  const sw         = props.sw;
  const onClose    = props.onClose;
  const onUnlocked = props.onUnlocked;

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr]           = useState("");
  const [busy, setBusy]         = useState(false);

  async function submit(e) {
    if (e) e.preventDefault();
    setErr("");
    if (!username.trim() || !password) {
      setErr("Username and password are required.");
      return;
    }
    setBusy(true);
    try {
      const result = await loginRequest(username.trim(), password, [sw.name]);
      setTokenFor(sw.name, result.token, username.trim());
      onUnlocked();
    } catch (e2) {
      setErr(e2.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={function(e){ e.stopPropagation(); }}>
        <div className="modal-head">
          <i className="uil uil-lock-open-alt" />
          <div>
            <div className="modal-title">Unlock {sw.name}</div>
            <div className="modal-sub">{sw.host} · {sw.device_type}</div>
          </div>
          <button className="icon-btn" onClick={onClose} title="Close">
            <i className="uil uil-times" />
          </button>
        </div>
        <form className="modal-body" onSubmit={submit}>
          <label>
            <div className="label-text">SSH username</div>
            <input type="text" value={username} autoFocus
                   autoComplete="username"
                   onChange={function(e){ setUsername(e.target.value); }} />
          </label>
          <label>
            <div className="label-text">SSH password</div>
            <input type="password" value={password}
                   autoComplete="current-password"
                   onChange={function(e){ setPassword(e.target.value); }} />
          </label>
          {err ? <div className="alert error">{err}</div> : null}
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="primary" disabled={busy}>
              {busy ? "Unlocking…" : "Unlock"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// CommandsTab — manual ad-hoc command runner
// ────────────────────────────────────────────────────────────────────
function CommandsTab(props) {
  const sw = props.sw;
  const [commands, setCommands] = useState([]);
  const [filter, setFilter]     = useState("");
  const [key, setKey]           = useState("");
  const [rawCmd, setRawCmd]     = useState("");
  const [output, setOutput]     = useState("");
  const [error, setError]       = useState("");
  const [busy, setBusy]         = useState(false);
  const [lastCmd, setLastCmd]   = useState("");
  const [fix, setFix]           = useState(null);   // agent command suggestions
  const [fixing, setFixing]     = useState(false);
  const rawRef                  = React.useRef(null);

  useEffect(function() {
    api("/api/commands?device_type=" + encodeURIComponent(sw.device_type))
      .then(function(list) {
        setCommands(list);
        if (list.length) setKey(list[0].key);
      })
      .catch(function(e){ setError(e.message); });
  }, [sw.device_type]);

  const filtered = useMemo(function() {
    if (!filter.trim()) return commands;
    const f = filter.trim().toLowerCase();
    return commands.filter(function(c){
      return (c.key + " " + c.command).toLowerCase().indexOf(f) >= 0;
    });
  }, [commands, filter]);

  async function run(useRaw, overrideCmd) {
    setBusy(true); setError(""); setOutput(""); setFix(null);
    const attempted = overrideCmd != null ? overrideCmd
                    : useRaw ? rawCmd.trim() : null;
    try {
      const body = (useRaw || overrideCmd != null)
        ? { command_raw: attempted }
        : { command_key: key };
      const r = await api("/api/switches/" + encodeURIComponent(sw.name) + "/run",
        { method: "POST", body: JSON.stringify(body) }, sw.name);
      setOutput(r.output || "");
      setLastCmd(r.command);
      if (!r.success) {
        setError(r.error || "command failed");
        askAgent(r.command, r.error || "", r.output || "");
        // Hand the failure to the NOC Assistant chatbot as well — it will
        // recommend the right command with an Apply button.
        window.dispatchEvent(new CustomEvent("noc-command-failed", {
          detail: { switch: sw.name, command: r.command,
                    error: r.error || "", output: r.output || "" },
        }));
      }
    } catch (e) {
      setError(e.message);
      if (attempted) {
        askAgent(attempted, e.message, "");
        window.dispatchEvent(new CustomEvent("noc-command-failed", {
          detail: { switch: sw.name, command: attempted,
                    error: e.message, output: "" },
        }));
      }
    }
    finally { setBusy(false); }
  }

  // Ask the agent what the operator probably meant. Read-only suggestions only.
  async function askAgent(cmd, errText, outText) {
    if (!cmd) return;
    setFixing(true);
    try {
      const r = await api("/api/switches/" + encodeURIComponent(sw.name) +
                          "/suggest-command",
        { method: "POST", body: JSON.stringify({
            command: cmd, error: errText, output: outText }) }, sw.name);
      if (r && r.suggestions && r.suggestions.length) setFix(r);
    } catch (e) { /* advisor is optional — stay quiet */ }
    finally { setFixing(false); }
  }

  // Applying a suggestion puts it in the command bar — it does NOT run it.
  // The operator reviews the filled-in command and presses Send themselves.
  function useSuggestion(cmd) {
    setRawCmd(cmd);
    setFix(null);
    if (rawRef.current) rawRef.current.focus();
  }

  // The NOC Assistant chatbot's Apply button lands here: it dispatches a
  // noc-apply-command event and we fill the command bar with the fix.
  useEffect(function() {
    function onApply(ev) {
      const d = ev.detail || {};
      if (d.switch && d.switch !== sw.name) return;
      if (!d.command) return;
      setRawCmd(d.command);
      setFix(null);
      if (rawRef.current) rawRef.current.focus();
    }
    window.addEventListener("noc-apply-command", onApply);
    return function(){ window.removeEventListener("noc-apply-command", onApply); };
  }, [sw.name]);

  return (
    <div className="tab-body">
      {/* Predefined-command picker with search filter */}
      <div className="section-title">
        <i className="uil uil-list-ul" /> Predefined commands
      </div>
      <div className="row">
        <input type="text"
               placeholder="Search predefined commands…"
               value={filter}
               onChange={function(e){ setFilter(e.target.value); }}
               style={{maxWidth:260}} />
        <select value={key} onChange={function(e){ setKey(e.target.value); }}
                style={{flex:1, minWidth:280}}>
          {filtered.length === 0
            ? <option value="">— no commands match filter —</option>
            : null}
          {filtered.map(function(c){
            return <option key={c.key} value={c.key}>{c.key} — {c.command}</option>;
          })}
        </select>
        <button className="primary" onClick={function(){ run(false); }}
                disabled={busy || !key || filtered.length === 0}>
          {busy ? "Running…" : "Run selected"}
        </button>
      </div>

      {/* Manual / raw SSH command */}
      <div className="section-title" style={{marginTop:22}}>
        <i className="uil uil-terminal" /> Manual SSH command
      </div>
      <div className="muted small" style={{marginBottom:6}}>
        Type any show/display command to run it verbatim on
        <strong> {sw.name}</strong>. Destructive verbs
        (<code>reboot</code>, <code>delete</code>, <code>erase</code>,
        <code>format</code>, <code>factory</code>) are refused for safety —
        for those, use a regular SSH terminal.
      </div>
      <form onSubmit={function(e){ e.preventDefault(); run(true); }} className="row">
        <input type="text" value={rawCmd} ref={rawRef}
               placeholder={"e.g. " + (sw.device_type === "hp_comware"
                                       ? "display device manuinfo"
                                       : "show system")}
               onChange={function(e){ setRawCmd(e.target.value); }}
               style={{flex:1}} />
        <button type="submit" className="primary" disabled={busy || !rawCmd.trim()}>
          {busy ? "Sending…" : "Send raw command"}
        </button>
      </form>

      {lastCmd ? <div className="muted small" style={{marginTop:10}}>Last command: <code>{lastCmd}</code></div> : null}
      {error ? <div className="alert error">{error}</div> : null}

      {fixing ? (
        <div className="muted small" style={{marginTop:8}}>
          <i className="uil uil-robot" /> NOC Assistant is working out what you meant…
        </div>
      ) : null}

      {fix ? (
        <div className="fix-card">
          <div className="fix-head">
            <i className="uil uil-robot" />
            <div>
              <strong>NOC Assistant</strong>
              <div className="muted small">
                {fix.explanation
                  ? fix.explanation
                  : fix.is_syntax_error
                    ? "That command isn't valid on this switch (" + sw.device_type +
                      "). Did you mean one of these?"
                    : "Here are supported commands you can run instead."}
              </div>
            </div>
            <button className="icon-btn" title="Dismiss"
                    onClick={function(){ setFix(null); }}>
              <i className="uil uil-times" />
            </button>
          </div>
          <div className="fix-list">
            {fix.suggestions.map(function(sg){
              return (
                <button key={sg.command} className={cls("fix-chip", "c-" + sg.confidence)}
                        title={sg.reason}
                        onClick={function(){ useSuggestion(sg.command); }}>
                  <code>{sg.command}</code>
                  <span className="fix-label">{sg.label}</span>
                  <span className="fix-apply">Apply</span>
                </button>
              );
            })}
          </div>
          <div className="muted small fix-foot">
            Apply puts the command in the bar above — review it, then press
            Send. Only read-only commands are ever suggested.
          </div>
        </div>
      ) : null}

      {output ? <pre className="output">{output}</pre> : null}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// PortStatsTab — live port traffic. Live polling is SERVER-SIDE (persists
// across navigation); this tab reads the latest rows and lets you control
// that single server-side schedule.
// ────────────────────────────────────────────────────────────────────
function PortStatsTab(props) {
  const sw = props.sw;
  const [data, setData] = useState(null);
  const [err, setErr]   = useState("");
  const [busy, setBusy] = useState(false);

  // Server-side auto-capture setting (the ONE source of truth for live polling)
  const [setting, setSetting]       = useState(null);
  const [savingPoll, setSavingPoll] = useState(false);

  // Lightweight DB auto-refresh (browser-side, just re-reads latest rows)
  const autoRefresh    = props.autoRefresh;
  const setAutoRefresh = props.setAutoRefresh;
  const [nextRefresh, setNextRefresh] = useState(10);
  const lastRefreshAt = React.useRef(Date.now());

  // History picker — view any past capture, not just the latest
  const [captures, setCaptures]               = useState([]);
  const [selectedCapture, setSelectedCapture] = useState(null); // null = latest

  // Delta window and display units come from the PARENT so they persist when
  // the user switches tabs (this component unmounts on switch). Falls back to
  // local state if a caller doesn't pass them.
  const [deltaIntervalLocal, setDeltaIntervalLocal] = useState("1m");
  const [unitModeLocal, setUnitModeLocal]           = useState("auto");
  const deltaInterval    = props.deltaInterval    !== undefined ? props.deltaInterval    : deltaIntervalLocal;
  const setDeltaInterval = props.setDeltaInterval  || setDeltaIntervalLocal;
  const unitMode         = props.unitMode         !== undefined ? props.unitMode         : unitModeLocal;
  const setUnitMode      = props.setUnitMode       || setUnitModeLocal;

  const load = useCallback(async function() {
    try {
      let d;
      const wantDeltas = deltaInterval !== "off";

      // Helper: fetch absolute counters (latest or a chosen historical capture).
      const loadAbsolute = async function() {
        if (selectedCapture) {
          const rows = await api(
            "/api/port-stats?switch_name=" + encodeURIComponent(sw.name) +
            "&captured_at=" + encodeURIComponent(selectedCapture) + "&limit=1000",
            { cache: "no-store" });
          return { switch: sw.name, captured_at: selectedCapture, ports: rows };
        }
        return await api("/api/port-stats/latest?switch_name=" + encodeURIComponent(sw.name),
                         { cache: "no-store" });
      };

      if (wantDeltas) {
        // Try the deltas endpoint. If it's unreachable (e.g. the backend hasn't
        // been rebuilt with this endpoint yet) fall back to absolute counters so
        // the table ALWAYS renders — the delta feature can never break the view.
        try {
          d = await api(
            "/api/port-stats/deltas?switch_name=" + encodeURIComponent(sw.name) +
            "&interval=" + encodeURIComponent(deltaInterval) +
            (selectedCapture ? "&at=" + encodeURIComponent(selectedCapture) : ""),
            { cache: "no-store" });
          d.hasDeltas = true;
          d.captured_at = d.current_captured_at || d.captured_at;
        } catch (deltaErr) {
          d = await loadAbsolute();
          d.hasDeltas = false;
          d.deltaUnavailable = true;   // surface a hint in the UI
        }
      } else {
        d = await loadAbsolute();
      }

      setData(d); setErr("");
      lastRefreshAt.current = Date.now();
    } catch (e) { setErr(e.message); }
  }, [sw.name, selectedCapture, deltaInterval]);

  const loadCaptures = useCallback(async function() {
    try {
      const list = await api("/api/port-stats/captures?switch_name=" + encodeURIComponent(sw.name));
      setCaptures(list);
    } catch (_) { /* non-fatal */ }
  }, [sw.name]);

  const loadSetting = useCallback(async function() {
    try {
      const s = await api("/api/auto-capture/" + encodeURIComponent(sw.name));
      setSetting(s);
    } catch (_) { /* non-fatal */ }
  }, [sw.name]);

  const captureNow = useCallback(async function() {
    setBusy(true); setErr("");
    try {
      await api("/api/switches/" + encodeURIComponent(sw.name) + "/capture-port-stats",
                { method: "POST" }, sw.name);
      setSelectedCapture(null);   // jump back to latest to show the fresh capture
      await load();
      await loadCaptures();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }, [sw.name, load, loadCaptures]);

  // Enable/disable the SERVER-SIDE live polling (persists across navigation)
  const setPolling = useCallback(async function(enabled, intervalSec) {
    setSavingPoll(true); setErr("");
    try {
      const sec = intervalSec != null ? intervalSec
                 : (setting && setting.port_stats_interval_seconds) || 30;
      await api("/api/auto-capture/" + encodeURIComponent(sw.name) + "/port-stats",
                { method: "PUT",
                  body: JSON.stringify({ interval_seconds: sec, enabled: enabled }) });
      await loadSetting();
    } catch (e) { setErr("Live polling change failed: " + (e.message || "network error")); }
    finally { setSavingPoll(false); }
  }, [sw.name, setting, loadSetting]);

  // Initial fetch
  useEffect(function(){ load(); loadCaptures(); loadSetting(); }, [load, loadCaptures, loadSetting]);

  // Auto-refresh from DB (lightweight). Also re-pulls the setting so the
  // countdown / live badge stays in sync with the server.
  useEffect(function() {
    if (!autoRefresh) return;
    const t = setInterval(function(){
      load();
      loadSetting();
      lastRefreshAt.current = Date.now();
    }, 10000);
    return function(){ clearInterval(t); };
  }, [autoRefresh, load, loadSetting]);

  // 1-second tick for the DB-refresh countdown
  useEffect(function() {
    if (!autoRefresh) return;
    const t = setInterval(function() {
      const el = Math.floor((Date.now() - lastRefreshAt.current) / 1000);
      setNextRefresh(Math.max(0, 10 - (el % 10)));
    }, 1000);
    return function(){ clearInterval(t); };
  }, [autoRefresh]);

  const pollOn       = !!(setting && setting.port_stats_enabled);
  const pollInterval = (setting && setting.port_stats_interval_seconds) || 30;

  return (
    <div className="tab-body">
      <div className="row" style={{flexWrap:"wrap", gap:8, alignItems:"center"}}>
        <button className="primary" onClick={captureNow} disabled={busy}>
          {busy ? "Capturing…" : "Capture now"}
        </button>
        <button className="secondary" onClick={function(){ load(); loadSetting(); lastRefreshAt.current = Date.now(); }} disabled={busy}>
          <i className="uil uil-refresh" /> Refresh
        </button>

        {/* Browser-side lightweight DB re-read */}
        <label className="checkbox" title="Re-reads the latest rows from the DB every 10s. Lightweight.">
          <input type="checkbox" checked={autoRefresh}
                 onChange={function(e){ setAutoRefresh(e.target.checked); }} />
          <span>Auto-refresh view (10s)
            {autoRefresh ? <span className="muted small"> · {nextRefresh}s</span> : null}
          </span>
        </label>

        {/* SERVER-SIDE live polling — the single source of truth. Persists. */}
        <label className="checkbox"
               title="Runs SSH captures on the server every interval. Keeps running even if you close this tab or the browser."
               style={{borderLeft:"2px solid var(--accent, #2563eb)", paddingLeft:8}}>
          <input type="checkbox" checked={pollOn} disabled={savingPoll}
                 onChange={function(e){ setPolling(e.target.checked, pollInterval); }} />
          <span>
            <b>Live polling (server)</b>
            {pollOn ? <span style={{color:"#16a34a", fontSize:11}}> ● running every {pollInterval}s</span>
                    : <span className="muted small"> · off</span>}
            {savingPoll ? <span className="muted small"> · saving…</span> : null}
          </span>
        </label>

        <select value={pollInterval} disabled={savingPoll}
                title="How often the server captures port stats"
                onChange={function(e){ setPolling(pollOn, Number(e.target.value)); }}
                style={{fontSize:12, padding:"3px 8px", borderRadius:4,
                        border:"1px solid var(--border)", background:"var(--panel-2)"}}>
          <option value={15}>every 15s</option>
          <option value={30}>every 30s</option>
          <option value={60}>every 1 min</option>
          <option value={120}>every 2 min</option>
          <option value={300}>every 5 min</option>
          <option value={600}>every 10 min</option>
        </select>

        {/* Delta window — shows NEW packets/bytes per interface over this span */}
        <label className="muted small" style={{display:"flex", alignItems:"center", gap:6,
               borderLeft:"2px solid var(--accent, #2563eb)", paddingLeft:8}}>
          <span title="Subtracts an earlier capture to show how much new traffic arrived in this window">
            New traffic over
          </span>
          <select value={deltaInterval}
                  onChange={function(e){ setDeltaInterval(e.target.value); }}
                  style={{fontSize:12, padding:"3px 8px", borderRadius:4,
                          border:"1px solid var(--border)", background:"var(--panel-2)"}}>
            <option value="1m">1 min</option>
            <option value="15m">15 min</option>
            <option value="1h">1 hour</option>
            <option value="12h">12 hours</option>
            <option value="24h">24 hours</option>
            <option value="off">off</option>
          </select>
        </label>

        {/* Units — switch how packet/byte numbers are displayed */}
        <label className="muted small" style={{display:"flex", alignItems:"center", gap:6}}>
          <span title="How to display packet and byte counts">Units</span>
          <select value={unitMode}
                  onChange={function(e){ setUnitMode(e.target.value); }}
                  style={{fontSize:12, padding:"3px 8px", borderRadius:4,
                          border:"1px solid var(--border)", background:"var(--panel-2)"}}>
            <option value="auto">Auto</option>
            <option value="exact">Exact (full number)</option>
            <option value="K">Thousands (K / KB)</option>
            <option value="M">Millions (M / MB)</option>
            <option value="B">Billions (B / GB)</option>
            <option value="T">Trillions (T / TB)</option>
          </select>
        </label>

        {captures.length > 1 && (
          <select value={selectedCapture || ""}
                  title="View a past capture instead of the latest"
                  onChange={function(e){ setSelectedCapture(e.target.value || null); }}
                  style={{fontSize:12, padding:"3px 8px", borderRadius:4, maxWidth:230,
                          border:"1px solid var(--border)", background:"var(--panel-2)"}}>
            <option value="">▶ Latest capture</option>
            {captures.map(function(c){
              return <option key={c.captured_at} value={c.captured_at}>
                {istTime(c.captured_at)} ({c.port_count}p)
              </option>;
            })}
          </select>
        )}

        <span className="muted small" style={{ marginLeft: "auto", textAlign: "right" }}>
          {data && data.captured_at
            ? <span>Captured <b>{istTime(data.captured_at)} IST</b> <span style={{opacity:0.7}}>({ago(data.captured_at)})</span></span>
            : "no data"}
          {captures.length > 0 ? <span style={{opacity:0.7}}> · {captures.length} in DB</span> : ""}
        </span>
      </div>

      {/* Stale-data hint only when server polling is OFF and not viewing history */}
      {!pollOn && !selectedCapture && data && data.captured_at &&
        (Date.now() - new Date(data.captured_at).getTime() > 5*60*1000) ? (
        <div className="alert error" style={{background:"#fef3c7",borderColor:"#fde68a",color:"#92400e"}}>
          <i className="uil uil-info-circle" />&nbsp;
          The latest row is over 5 minutes old. Tick <strong>Live polling (server)</strong>
          above to have the server capture fresh data automatically — it keeps running
          even when you leave this page.
        </div>
      ) : null}

      {err ? <div className="alert error">{err}</div> : null}

      {data && data.ports && data.ports.length > 0 ? (
        <div className="table-wrap">
          {data.hasDeltas ? (
            <div className="muted small" style={{margin:"4px 2px 8px", lineHeight:1.5}}>
              New traffic measured over <strong>{fmtDur(data.window_seconds)}</strong>
              {data.baseline_captured_at
                ? <span> — from {istTime(data.baseline_captured_at)} to {istTime(data.current_captured_at)}</span>
                : null}
              {data.partial
                ? <span style={{color:"#d97706"}}> · history shorter than the selected window, showing the largest span available</span>
                : null}
              {data.window_seconds === 0
                ? <span style={{color:"#d97706"}}> · only one capture exists so far — deltas appear once a second capture lands</span>
                : null}
            </div>
          ) : null}
          {data.deltaUnavailable ? (
            <div className="muted small" style={{margin:"4px 2px 8px", color:"#d97706"}}>
              Showing lifetime counters only. The per-interval “new traffic” endpoint
              isn’t reachable yet — rebuild the backend container
              (<code>docker compose up --build -d backend</code>) to enable the delta columns.
            </div>
          ) : null}
          <table>
            <thead>
              <tr>
                <th>Interface</th>
                <th>State</th>
                <th>Description</th>
                <th className="num">In packets</th>
                <th className="num">Out packets</th>
                {data.hasDeltas ? (
                  <th className="num" title="New inbound packets that arrived during the window"
                      style={{color:"var(--accent, #2563eb)"}}>New In · {fmtDur(data.window_seconds)}</th>
                ) : null}
                {data.hasDeltas ? (
                  <th className="num" title="New outbound packets sent during the window"
                      style={{color:"var(--accent, #2563eb)"}}>New Out · {fmtDur(data.window_seconds)}</th>
                ) : null}
                <th className="num">Total</th>
                <th className="num">In bytes</th>
                <th className="num">Out bytes</th>
                <th className="num">Errors</th>
              </tr>
            </thead>
            <tbody>
              {data.ports.slice().sort(function(a,b){
                // When showing deltas, sort by busiest in the window; else by lifetime total.
                if (data.hasDeltas) {
                  const da = (a.delta_in_packets||0) + (a.delta_out_packets||0);
                  const db_ = (b.delta_in_packets||0) + (b.delta_out_packets||0);
                  if (db_ !== da) return db_ - da;
                }
                return (b.total_packets||0) - (a.total_packets||0);
              }).map(function(p) {
                const total = p.total_packets != null ? p.total_packets : (p.in_packets + p.out_packets);
                const errors = (p.in_errors||0) + (p.out_errors||0);
                const sc = p.link_state === "UP" ? "#16a34a"
                         : p.link_state === "DOWN" ? "#dc2626" : "#9ca3af";

                // Render a delta cell: number when known, else "reset"/"—".
                const deltaCell = function(val, byteVal) {
                  if (p.reset) {
                    return <td className="num muted" title="Counter reset (switch reboot or cleared) between the two captures">reset</td>;
                  }
                  if (val === null || val === undefined) {
                    return <td className="num muted" title="No earlier capture for this interface yet">—</td>;
                  }
                  const tip = Number(val).toLocaleString() + " packets" +
                              (byteVal != null ? "  ·  " + fmtBytes(byteVal) : "");
                  return (
                    <td className="num" title={tip}
                        style={{color: val > 0 ? "#16a34a" : "var(--text-muted, #6b7280)", fontWeight:600}}>
                      {val > 0 ? "+" : ""}{fmtUnit(val, unitMode, false)}
                    </td>
                  );
                };

                return (
                  <tr key={p.interface}>
                    <td><code style={{fontSize:12}}>{p.interface}</code></td>
                    <td style={{fontWeight:600, fontSize:11, color:sc}}>{p.link_state || "—"}</td>
                    <td className="muted small" style={{whiteSpace:"normal", maxWidth:320}}>
                      {p.port_description || "—"}
                    </td>
                    <td className="num" title={fmt(p.in_packets) + " packets"}>{fmtUnit(p.in_packets, unitMode, false)}</td>
                    <td className="num" title={fmt(p.out_packets) + " packets"}>{fmtUnit(p.out_packets, unitMode, false)}</td>
                    {data.hasDeltas ? deltaCell(p.delta_in_packets,  p.delta_in_bytes)  : null}
                    {data.hasDeltas ? deltaCell(p.delta_out_packets, p.delta_out_bytes) : null}
                    <td className="num strong" title={fmt(total) + " packets"}>{fmtUnit(total, unitMode, false)}</td>
                    <td className="num" title={fmt(p.in_bytes) + " bytes"}>{fmtUnit(p.in_bytes, unitMode, true)}</td>
                    <td className="num" title={fmt(p.out_bytes) + " bytes"}>{fmtUnit(p.out_bytes, unitMode, true)}</td>
                    <td className="num" style={{color: errors>0 ? "#dc2626" : undefined}}>
                      {errors > 0 ? fmtUnit(errors, unitMode, false) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (!err ? <div className="muted">No port stats captured yet for this switch.</div> : null)}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// SnapshotsTab — config drift visualization
// ────────────────────────────────────────────────────────────────────
function SnapshotsTab(props) {
  const sw = props.sw;
  const [snaps, setSnaps]    = useState([]);
  const [active, setActive]  = useState(null);
  const [compareIds, setCompareIds] = useState([]); // up to 2 ids
  const [compareResult, setCompareResult] = useState(null);
  const [err, setErr]        = useState("");
  const [busy, setBusy]      = useState(false);

  const load = useCallback(async function() {
    try {
      const list = await api("/api/switches/" + encodeURIComponent(sw.name) + "/snapshots",
                             {}, sw.name);
      setSnaps(list); setErr("");
    } catch (e) { setErr(e.message); }
  }, [sw.name]);

  useEffect(function(){ load(); }, [load]);

  async function takeOne() {
    setBusy(true); setErr("");
    try {
      await api("/api/switches/" + encodeURIComponent(sw.name) + "/snapshot",
                { method: "POST" }, sw.name);
      await load();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  async function openSnap(id) {
    setCompareResult(null);
    try {
      const d = await api("/api/snapshots/" + id, {}, sw.name);
      setActive(d);
    } catch (e) { setErr(e.message); }
  }

  function toggleCompare(id, e) {
    e.stopPropagation();
    setCompareResult(null);
    setCompareIds(function(prev) {
      if (prev.indexOf(id) >= 0) return prev.filter(function(x){ return x !== id; });
      if (prev.length >= 2) return [prev[1], id];   // rolling window of 2
      return prev.concat([id]);
    });
  }

  async function runCompare() {
    if (compareIds.length !== 2) return;
    setBusy(true); setErr(""); setActive(null);
    const ids = [...compareIds].sort(function(a,b){ return a - b; });
    try {
      const d = await api("/api/snapshots/compare?a=" + ids[0] + "&b=" + ids[1],
                          {}, sw.name);
      setCompareResult(d);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  function clearCompare() {
    setCompareIds([]); setCompareResult(null);
  }

  return (
    <div className="tab-body">
      <div className="row">
        <button className="primary" onClick={takeOne} disabled={busy}>
          {busy ? "Taking snapshot…" : "Take snapshot now"}
        </button>
        <button className="secondary" onClick={load}>
          <i className="uil uil-refresh" /> Refresh
        </button>
        <span className="muted small" style={{ marginLeft: "auto" }}>
          {snaps.length} snapshot(s)
        </span>
      </div>

      {compareIds.length > 0 ? (
        <div className="snap-compare-bar">
          <i className="uil uil-exchange" />
          <span>
            Comparison: {compareIds.length === 2
              ? <React.Fragment>snapshot <strong>#{compareIds[0]}</strong> ↔ <strong>#{compareIds[1]}</strong></React.Fragment>
              : <React.Fragment>tick another snapshot to compare with <strong>#{compareIds[0]}</strong></React.Fragment>}
          </span>
          <button className="primary small" onClick={runCompare}
                  disabled={compareIds.length !== 2 || busy}
                  style={{marginLeft:"auto"}}>
            <i className="uil uil-exchange" /> Compare
          </button>
          <button className="secondary small" onClick={clearCompare}>Clear</button>
        </div>
      ) : null}

      {err ? <div className="alert error">{err}</div> : null}

      <div className="split">
        <div className="snap-list">
          {snaps.length === 0 ? <div className="muted">No snapshots yet.</div> : null}
          {snaps.map(function(s) {
            const isChecked = compareIds.indexOf(s.id) >= 0;
            return (
              <div key={s.id}
                   className={cls("snap-row", active && active.id === s.id && "active")}
                   onClick={function(){ openSnap(s.id); }}
                   style={{cursor:"pointer"}}>
                <input type="checkbox" checked={isChecked}
                       onClick={function(e){ toggleCompare(s.id, e); }}
                       onChange={function(){}}
                       title="Tick two snapshots, then click Compare" />
                <div className="snap-id">#{s.id}</div>
                <div className="snap-meta">
                  <div>{istTime(s.captured_at)}</div>
                  <div className="muted small">hash {s.config_hash.slice(0, 12)}</div>
                </div>
                {s.drift_detected
                  ? <span className="pill warn">drift</span>
                  : <span className="pill ok">stable</span>}
              </div>
            );
          })}
        </div>

        <div className="snap-detail">
          {compareResult ? (
            <React.Fragment>
              <div className="snap-detail-head">
                <div>
                  <strong>Comparing #{compareResult.a.id} ↔ #{compareResult.b.id}</strong>
                </div>
                <div>
                  {compareResult.identical
                    ? <span className="pill ok">identical</span>
                    : <span className="pill warn">differences found</span>}
                </div>
              </div>
              <div className="muted small" style={{margin:"6px 0"}}>
                <div>A · #{compareResult.a.id} {compareResult.a.switch_name} @ {istTime(compareResult.a.captured_at)}</div>
                <div>B · #{compareResult.b.id} {compareResult.b.switch_name} @ {istTime(compareResult.b.captured_at)}</div>
              </div>
              {compareResult.identical ? (
                <div className="muted" style={{marginTop:16}}>
                  Both snapshots have the same configuration hash — the running-configs
                  are byte-for-byte identical.
                </div>
              ) : (
                <pre className="diff diff-full">{colorizeDiff(compareResult.diff)}</pre>
              )}
            </React.Fragment>
          ) : active ? (
            <React.Fragment>
              <div className="snap-detail-head">
                <div>
                  <strong>Snapshot #{active.id}</strong> ·{" "}
                  {istTime(active.captured_at)}
                </div>
                <div>
                  {active.drift_detected
                    ? <span className="pill warn">drift from previous</span>
                    : <span className="pill ok">no drift</span>}
                </div>
              </div>
              {active.drift_detected && active.diff_from_prev ? (
                <React.Fragment>
                  <div className="muted small" style={{ margin: "12px 0 4px" }}>
                    Diff vs previous snapshot
                  </div>
                  <pre className="diff diff-full">{colorizeDiff(active.diff_from_prev)}</pre>
                </React.Fragment>
              ) : null}
              <div className="muted small" style={{ margin: "12px 0 4px" }}>
                Full config
              </div>
              <pre className="output">{active.config_text}</pre>
            </React.Fragment>
          ) : (
            <div className="muted">
              Click a snapshot on the left to view it, or tick the checkboxes
              on two snapshots and click <strong>Compare</strong> to diff any two.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function colorizeDiff(text) {
  return text.split("\n").map(function(line, i) {
    let cl = "";
    if (line.startsWith("+++") || line.startsWith("---")) cl = "d-meta";
    else if (line.startsWith("@@"))                       cl = "d-hunk";
    else if (line.startsWith("+"))                        cl = "d-add";
    else if (line.startsWith("-"))                        cl = "d-del";
    return <span key={i} className={cl}>{line + "\n"}</span>;
  });
}

// ────────────────────────────────────────────────────────────────────
// SettingsTab — auto-capture toggles per switch
// ────────────────────────────────────────────────────────────────────
function SettingsTab(props) {
  const sw = props.sw;
  const [settings, setSettings] = useState(null);
  const [err, setErr]   = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async function() {
    try {
      const s = await api("/api/auto-capture/" + encodeURIComponent(sw.name));
      setSettings(s); setErr("");
    } catch (e) { setErr(e.message); }
  }, [sw.name]);

  useEffect(function(){ load(); }, [load]);

  // All four PUTs send a JSON body instead of query params. Query-param PUTs
  // were the cause of "failed to fetch" — the JSON-body form is the standard
  // approach and works across every browser / network configuration.
  async function putPortStats(enabled, sec) {
    setBusy(true); setErr("");
    try {
      await api("/api/auto-capture/" + encodeURIComponent(sw.name) + "/port-stats",
                { method: "PUT",
                  body: JSON.stringify({ interval_seconds: sec, enabled: enabled }) });
      await load();
    } catch (e) { setErr("Port-stats save failed: " + (e.message || "network error")); }
    finally { setBusy(false); }
  }

  async function putSnap(enabled, min) {
    setBusy(true); setErr("");
    try {
      await api("/api/auto-capture/" + encodeURIComponent(sw.name),
                { method: "PUT",
                  body: JSON.stringify({ interval_minutes: min, enabled: enabled }) });
      await load();
    } catch (e) { setErr("Snapshot save failed: " + (e.message || "network error")); }
    finally { setBusy(false); }
  }

  const togglePortStats    = function(en){ putPortStats(en, settings.port_stats_interval_seconds || 30); };
  const changeInterval     = function(s){  putPortStats(settings.port_stats_enabled || false, s); };
  const toggleSnap         = function(en){ putSnap(en, settings.interval_minutes || 1440); };
  const changeSnapInterval = function(m){  putSnap(settings.enabled || false, m); };

  if (!settings) return <div className="tab-body"><div className="muted">Loading…</div></div>;

  return (
    <div className="tab-body">
      {err ? <div className="alert error">{err}</div> : null}

      <div className="setting-card">
        <div className="setting-head">
          <i className="uil uil-tachometer-fast" />
          <div>
            <div className="setting-title">Real-time port-stat polling</div>
            <div className="muted small">
              Background job polls this switch on a schedule and stores counters in <code>port_stats</code>.
            </div>
          </div>
        </div>
        <div className="row">
          <label className="checkbox">
            <input type="checkbox" checked={settings.port_stats_enabled}
                   onChange={function(e){ togglePortStats(e.target.checked); }} disabled={busy} />
            <span>Enabled</span>
          </label>
          <label>
            <span className="label-text">Interval</span>
            <select value={settings.port_stats_interval_seconds || 30}
                    onChange={function(e){ changeInterval(Number(e.target.value)); }} disabled={busy}>
              <option value={15}>15 seconds</option>
              <option value={30}>30 seconds</option>
              <option value={60}>1 minute</option>
              <option value={120}>2 minutes</option>
              <option value={300}>5 minutes</option>
              <option value={600}>10 minutes</option>
            </select>
          </label>
          <span className="muted small" style={{ marginLeft: "auto" }}>
            Last: {ago(settings.port_stats_last_captured_at)}
            {" · "}Next: {settings.port_stats_next_due_at ? ago(settings.port_stats_next_due_at) : "—"}
          </span>
        </div>
      </div>

      <div className="setting-card">
        <div className="setting-head">
          <i className="uil uil-shield-check" />
          <div>
            <div className="setting-title">Config snapshot / drift detection</div>
            <div className="muted small">
              Captures the running-config on a schedule and detects drift.
            </div>
          </div>
        </div>
        <div className="row">
          <label className="checkbox">
            <input type="checkbox" checked={settings.enabled}
                   onChange={function(e){ toggleSnap(e.target.checked); }} disabled={busy} />
            <span>Enabled</span>
          </label>
          <label>
            <span className="label-text">Interval</span>
            <select value={settings.interval_minutes || 1440}
                    onChange={function(e){ changeSnapInterval(Number(e.target.value)); }} disabled={busy}>
              <option value={1}>1 minute</option>
              <option value={15}>15 minutes</option>
              <option value={60}>1 hour</option>
              <option value={720}>12 hours</option>
              <option value={1440}>24 hours</option>
            </select>
          </label>
          <span className="muted small" style={{ marginLeft: "auto" }}>
            Last: {ago(settings.last_captured_at)}
            {" · "}Next: {settings.next_due_at ? ago(settings.next_due_at) : "—"}
          </span>
        </div>

        {/* Surface WHY auto-capture is failing (e.g. bad SSH credentials)
            instead of letting it fail silently. */}
        {settings.enabled && settings.last_snapshot_status === "error" ? (
          <div className="alert error" style={{marginTop:8, fontSize:12}}>
            <i className="uil uil-exclamation-triangle" />{" "}
            <strong>Last auto-snapshot failed.</strong>{" "}
            {settings.last_snapshot_error || "Unknown error."}
            <div className="muted small" style={{marginTop:4}}>
              This is usually wrong SSH credentials stored for the switch, or the
              switch being unreachable. Re-log in with the correct password (that
              syncs the credentials the scheduler uses), or check connectivity.
            </div>
          </div>
        ) : null}
        {settings.enabled && settings.last_snapshot_status === "ok" ? (
          <div className="muted small" style={{marginTop:6, color:"#16a34a"}}>
            <i className="uil uil-check-circle" /> Last auto-snapshot succeeded.
          </div>
        ) : null}
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// SwitchPanel — full controls for an unlocked switch
// ────────────────────────────────────────────────────────────────────
function SwitchPanel(props) {
  const sw        = props.sw;
  const username  = props.username;
  const onLock    = props.onLock;
  const onDeleted = props.onDeleted;
  const [tab, setTab] = useState("ports");

  // Only the lightweight DB-refresh toggle is browser-side now. The real
  // live capture is server-side (stored in DB), so it no longer needs any
  // state here and persists across all navigation automatically.
  const [psAutoRefresh, setPsAutoRefresh] = useState(true);
  // Held in the parent so they survive tab switches (PortStatsTab unmounts on switch).
  const [psDeltaInterval, setPsDeltaInterval] = useState("1m");
  const [psUnitMode, setPsUnitMode]           = useState("auto");
  const [deleting, setDeleting] = useState(false);

  async function deleteSwitch() {
    const ok = window.confirm(
      "Delete switch \"" + sw.name + "\"?\n\n" +
      "This permanently removes the switch AND all of its stored data:\n" +
      "config snapshots, port stats, ARP entries, command logs and " +
      "auto-capture settings.\n\nThis cannot be undone."
    );
    if (!ok) return;

    setDeleting(true);
    try {
      await api(
        "/api/switches/" + encodeURIComponent(sw.name),
        { method: "DELETE" },
        sw.name
      );
      if (onDeleted) onDeleted(sw.name);
    } catch (e) {
      window.alert("Delete failed: " + (e.message || "unknown error"));
    } finally {
      setDeleting(false);
    }
  }

  const tabs = [
    { key: "ports",     label: "Port stats",   icon: "tachometer-fast" },
    { key: "snapshots", label: "Config drift", icon: "shield-check"    },
    { key: "commands",  label: "Run command",  icon: "terminal"        },
    { key: "settings",  label: "Auto-capture", icon: "setting"         },
  ];

  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-server" />
          <div>
            <div className="panel-title">{sw.name}</div>
            <div className="panel-sub">
              {sw.host} · {sw.device_type}
              {sw.location ? " · " + sw.location : ""}
            </div>
          </div>
        </div>
        <div className="panel-id-right">
          <span className="pill ok"><i className="uil uil-lock-open-alt" /> unlocked as {username || "admin"}</span>
          <button className="secondary small" onClick={onLock} title="Lock this switch">
            <i className="uil uil-lock" /> Lock
          </button>
          <button className="secondary small" onClick={deleteSwitch} disabled={deleting}
                  title="Delete this switch and all its data"
                  style={{ color: "#dc2626", borderColor: "#fca5a5" }}>
            <i className="uil uil-trash-alt" /> {deleting ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>

      <div className="tabs">
        {tabs.map(function(t) {
          return (
            <button key={t.key}
                    className={cls("tab-btn", tab === t.key && "active")}
                    onClick={function(){ setTab(t.key); }}>
              <i className={"uil uil-" + t.icon} /> {t.label}
            </button>
          );
        })}
      </div>

      {tab === "ports"     ? <PortStatsTab sw={sw}
                               autoRefresh={psAutoRefresh}
                               setAutoRefresh={setPsAutoRefresh}
                               deltaInterval={psDeltaInterval}
                               setDeltaInterval={setPsDeltaInterval}
                               unitMode={psUnitMode}
                               setUnitMode={setPsUnitMode} /> : null}
      {tab === "snapshots" ? <SnapshotsTab sw={sw} /> : null}
      {tab === "commands"  ? <CommandsTab sw={sw} />  : null}
      {tab === "settings"  ? <SettingsTab sw={sw} />  : null}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// LockedSwitchPanel — shown when admin selects a switch they didn't unlock
// ────────────────────────────────────────────────────────────────────
function LockedSwitchPanel(props) {
  const sw            = props.sw;
  const onUnlockClick = props.onUnlockClick;
  const onDeleted = props.onDeleted;
  const [deleting, setDeleting] = useState(false);
  async function deleteSwitch() {
    const ok = window.confirm(
      "Delete switch \"" + sw.name + "\"?\n\n" +
      "This permanently removes the switch and all of its stored data. " +
      "It does NOT require valid credentials — use this to remove dead or " +
      "misconfigured switches.\n\nThis cannot be undone."
    );
    if (!ok) return;
    setDeleting(true);
    try {
      await api("/api/switches/" + encodeURIComponent(sw.name), { method: "DELETE" });
      if (onDeleted) onDeleted(sw.name);
    } catch (e) {
      window.alert("Delete failed: " + (e.message || "unknown error"));
    } finally {
      setDeleting(false);
    }
  }
  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-server" />
          <div>
            <div className="panel-title">{sw.name}</div>
            <div className="panel-sub">
              {sw.host} · {sw.device_type}
              {sw.location ? " · " + sw.location : ""}
            </div>
          </div>
        </div>
        <div className="panel-id-right">
          <span className="pill warn"><i className="uil uil-lock" /> locked</span>
          <button className="secondary small" onClick={deleteSwitch} disabled={deleting}
                  title="Delete this switch and all its data"
                  style={{ color: "#dc2626", borderColor: "#fca5a5" }}>
            <i className="uil uil-trash-alt" /> {deleting ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>

      <div className="locked-empty">
        <i className="uil uil-lock locked-icon" />
        <div className="locked-title">Credentials required</div>
        <div className="locked-sub">
          You haven't entered SSH credentials for <strong>{sw.name}</strong> in this session.
          Provide them to view port stats, run commands, or inspect config drift.
        </div>
        <button className="primary" onClick={onUnlockClick}>
          <i className="uil uil-lock-open-alt" /> Enter credentials for {sw.name}
        </button>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Add-switch dialog (for registering a new switch)
// ────────────────────────────────────────────────────────────────────
function AddSwitchDialog(props) {
  const onClose   = props.onClose;
  const onCreated = props.onCreated;
  const [form, setForm] = useState({
    name: "", host: "", port: 22, device_type: "hp_comware",
    username: "", password: "", location: "",
  });
  const [err, setErr]   = useState("");
  const [busy, setBusy] = useState(false);

  function upd(k, v) { setForm(function(p){ const n = Object.assign({}, p); n[k] = v; return n; }); }

  async function save(e) {
    if (e) e.preventDefault();
    setErr("");
    if (!form.name || !form.host || !form.username || !form.password) {
      setErr("Name, host, username and password are required.");
      return;
    }
    setBusy(true);
    try {
      const data = await api("/api/switches", {
        method: "POST",
        body: JSON.stringify(Object.assign({}, form, { port: Number(form.port) })),
      });
      onCreated(data);
    } catch (e2) { setErr(e2.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={function(e){ e.stopPropagation(); }}>
        <div className="modal-head">
          <i className="uil uil-plus-circle" />
          <div>
            <div className="modal-title">Add switch</div>
            <div className="modal-sub">Register a new device in the portal</div>
          </div>
          <button className="icon-btn" onClick={onClose}><i className="uil uil-times" /></button>
        </div>
        <form className="modal-body" onSubmit={save}>
          <div className="row two">
            <label><div className="label-text">Name</div>
              <input value={form.name} onChange={function(e){ upd("name", e.target.value); }} autoFocus />
            </label>
            <label><div className="label-text">Host / IP</div>
              <input value={form.host} onChange={function(e){ upd("host", e.target.value); }} />
            </label>
          </div>
          <div className="row two">
            <label><div className="label-text">Port</div>
              <input type="number" value={form.port} onChange={function(e){ upd("port", e.target.value); }} />
            </label>
            <label><div className="label-text">Device type</div>
              <select value={form.device_type} onChange={function(e){ upd("device_type", e.target.value); }}>
                <option value="hp_comware">HP Comware</option>
                <option value="aruba_aoscx">Aruba AOS-CX</option>
                <option value="aruba_procurve">Aruba ProVision (ProCurve)</option>
                <option value="huawei">Huawei</option>
                <option value="huawei_vrp">Huawei VRP v8</option>
              </select>
            </label>
          </div>
          <div className="row two">
            <label><div className="label-text">SSH username</div>
              <input value={form.username} autoComplete="off"
                     onChange={function(e){ upd("username", e.target.value); }} />
            </label>
            <label><div className="label-text">SSH password</div>
              <input type="password" value={form.password} autoComplete="off"
                     onChange={function(e){ upd("password", e.target.value); }} />
            </label>
          </div>
          <label><div className="label-text">Location (optional)</div>
            <input value={form.location} onChange={function(e){ upd("location", e.target.value); }} />
          </label>
          <div className="muted small">
            These per-switch credentials are stored in the database and used by
            the background scheduler. Interactive operations require an admin
            session you provide at login.
          </div>
          {err ? <div className="alert error">{err}</div> : null}
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="primary" disabled={busy}>
              {busy ? "Saving…" : "Add switch"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// SERVER MONITORING (additive) — HPE iLO-style Performance view.
// Self-contained: manages its own server list; only mounted from the
// 'Servers' tab. No switch code is touched.
// ────────────────────────────────────────────────────────────────────

const ILO_RANGES = [
  { key: "10min", label: "10 min",  sub: "10 minutes",  tick: "twenty-second intervals" },
  { key: "1hr",   label: "1 hr",    sub: "hour",        tick: "twenty-second intervals" },
  { key: "24hr",  label: "24 hr",   sub: "24 hours",    tick: "five-minute intervals" },
  { key: "1week", label: "1 week",  sub: "week",        tick: "thirty-minute intervals" },
];

function IloChart(props) {
  // Lightweight SVG line chart in the iLO style: grid, teal line, dot on last point.
  const points = props.points || [];
  const unit   = props.unit || "%";
  const W = 860, H = 320, padL = 46, padR = 16, padT = 10, padB = 34;
  const iw = W - padL - padR, ih = H - padT - padB;

  let maxY = 100;
  if (unit !== "%") {
    const mx = points.reduce(function(m, p){ return Math.max(m, p.v); }, 0);
    maxY = Math.max(10, Math.ceil(mx * 1.2 / 10) * 10);
  }
  const xs = function(i){ return padL + (points.length <= 1 ? iw : (i / (points.length - 1)) * iw); };
  const ys = function(v){ return padT + ih - (Math.min(v, maxY) / maxY) * ih; };

  const path = points.map(function(p, i){
    return (i === 0 ? "M" : "L") + xs(i).toFixed(1) + "," + ys(p.v).toFixed(1);
  }).join(" ");

  // x labels: ~5 evenly spaced timestamps (HH:MM)
  const labels = [];
  const nLab = Math.min(5, points.length);
  for (let k = 0; k < nLab; k++) {
    const i = Math.round((k / Math.max(1, nLab - 1)) * (points.length - 1));
    const d = new Date(points[i].t);
    labels.push({ x: xs(i), text: ("0"+d.getHours()).slice(-2) + ":" + ("0"+d.getMinutes()).slice(-2) });
  }
  const gridY = [0, 0.25, 0.5, 0.75, 1].map(function(f){ return padT + ih - f * ih; });

  return (
    <svg viewBox={"0 0 " + W + " " + H} className="ilo-chart" preserveAspectRatio="none">
      {gridY.map(function(gy, i){
        return <line key={"g"+i} x1={padL} y1={gy} x2={W-padR} y2={gy} className="ilo-grid" />;
      })}
      {[0.25, 0.5, 0.75].map(function(f, i){
        const gx = padL + f * iw;
        return <line key={"v"+i} x1={gx} y1={padT} x2={gx} y2={padT+ih} className="ilo-grid" />;
      })}
      <text x={padL-8} y={padT+8}      className="ilo-axis" textAnchor="end">{maxY}</text>
      <text x={padL-8} y={padT+ih/2+4} className="ilo-axis" textAnchor="end">{Math.round(maxY/2)}</text>
      <text x={padL-8} y={padT+ih+4}   className="ilo-axis" textAnchor="end">0</text>
      {labels.map(function(l, i){
        return <text key={"x"+i} x={l.x} y={H-10} className="ilo-axis" textAnchor="middle">{l.text}</text>;
      })}
      {points.length > 0 ? <path d={path} className="ilo-line" fill="none" /> : null}
      {points.length > 0 ? (
        <circle cx={xs(points.length-1)} cy={ys(points[points.length-1].v)} r="4" className="ilo-dot" />
      ) : null}
      {points.length === 0 ? (
        <text x={W/2} y={H/2} textAnchor="middle" className="ilo-axis">No data yet — polling every 20 seconds…</text>
      ) : null}
    </svg>
  );
}

function AddServerDialog(props) {
  const onClose = props.onClose, onCreated = props.onCreated;
  const [tab, setTab]       = useState("inventory");   // inventory | manual
  const [inv, setInv]       = useState([]);
  const [sel, setSel]       = useState({});
  const [filter, setFilter] = useState("");
  const [creds, setCreds]   = useState({ username: "", password: "" });

  // ── Bulk import from a spreadsheet (CSV / XLSX) ───────────────────────────
  // Two phases on purpose: the file is parsed and previewed first, so the
  // operator sees which column was read as the address and which rows were
  // skipped BEFORE anything is written.
  const fileRef             = React.useRef(null);
  const [preview, setPrev]  = useState(null);   // dry-run result
  const [upErr, setUpErr]   = useState("");
  const [upBusy, setUpBusy] = useState(false);
  const [bulkRes, setBulk]  = useState(null);

  async function sendFile(file, dryRun){
    const fd = new FormData();
    fd.append("file", file);
    fd.append("dry_run", dryRun ? "true" : "false");
    fd.append("username", creds.username || "");
    fd.append("password", creds.password || "");
    return api("/api/servers/bulk-upload", { method: "POST", body: fd });
  }

  async function onFilePicked(e){
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    setUpErr(""); setBulk(null); setPrev(null); setUpBusy(true);
    try {
      const r = await sendFile(file, true);
      r._file = file;                       // keep it for the commit phase
      setPrev(r);
    } catch (e2) { setUpErr(e2.message); }
    finally { setUpBusy(false); if (fileRef.current) fileRef.current.value = ""; }
  }

  async function commitUpload(){
    if (!preview || !preview._file) return;
    setUpErr(""); setUpBusy(true);
    try {
      const r = await sendFile(preview._file, false);
      setBulk(r); setPrev(null);
      if (r.added_count > 0 && props.onCreated) props.onCreated(r);
    } catch (e2) { setUpErr(e2.message); }
    finally { setUpBusy(false); }
  }
  const [form, setForm]     = useState({ name:"", host:"", username:"", password:"", location:"" });
  const [err, setErr]       = useState("");
  const [busy, setBusy]     = useState(false);
  const [result, setResult] = useState(null);

  useEffect(function(){
    api("/api/inventory/servers")
      .then(function(d){ setInv(d.servers || []); })
      .catch(function(e){ setErr(e.message); });
  }, []);

  function toggle(ip){
    setSel(function(p){ const n = Object.assign({}, p); if (n[ip]) delete n[ip]; else n[ip] = true; return n; });
  }

  const shown = inv.filter(function(r){
    if (!filter) return true;
    const f = filter.toLowerCase();
    return (r.ilo_ip + " " + r.hostname + " " + r.model + " " + r.solution +
            " " + r.rack + " " + (r.gpu_model || "") + " " + (r.owner || "") +
            " " + (r.team || "")).toLowerCase().indexOf(f) !== -1;
  });
  const chosen = Object.keys(sel);

  async function importSelected(e){
    if (e) e.preventDefault();
    setErr("");
    if (!chosen.length) { setErr("Select at least one server."); return; }
    if (!(creds.username && creds.password)) {
      setErr("Enter the iLO username and password for the selected servers.");
      return;
    }
    setBusy(true);
    try {
      const r = await api("/api/servers/import", {
        method: "POST",
        body: JSON.stringify({
          ilo_ips: chosen,
          username: creds.username,
          password: creds.password,
        }),
      });
      setResult(r);
      if (r.added_count > 0) onCreated(r);
    } catch (e2) { setErr(e2.message); }
    finally { setBusy(false); }
  }

  async function saveManual(e){
    if (e) e.preventDefault();
    setErr("");
    if (!form.name || !form.host || !form.username || !form.password) {
      setErr("Name, host, username and password are required."); return;
    }
    setBusy(true);
    try {
      const data = await api("/api/servers", { method:"POST", body: JSON.stringify(form) });
      if (!data.detected_source) {
        setErr("Added, but no metrics source responded: " + (data.detect_error || "unknown"));
        setBusy(false); return;
      }
      onCreated(data);
    } catch (e2) { setErr(e2.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={function(e){ e.stopPropagation(); }}>
        <div className="modal-head">
          <i className="uil uil-plus-circle" />
          <div>
            <div className="modal-title">Add servers</div>
            <div className="modal-sub">Pick from the iLO inventory, or add one manually</div>
          </div>
          <button className="icon-btn" onClick={onClose}><i className="uil uil-times" /></button>
        </div>

        <div className="modal-tabs">
          <button className={cls("modal-tab", tab === "inventory" && "active")}
                  onClick={function(){ setTab("inventory"); setErr(""); }}>
            <i className="uil uil-server-network" /> From inventory ({inv.length})
          </button>
          <button className={cls("modal-tab", tab === "manual" && "active")}
                  onClick={function(){ setTab("manual"); setErr(""); }}>
            <i className="uil uil-edit" /> Manual
          </button>
        </div>

        {tab === "inventory" ? (
          <form className="modal-body" onSubmit={importSelected}>
            {result ? (
              <div className="alert ok">
                Added {result.added_count}.
                {result.skipped.length ? " Skipped " + result.skipped.length + " already present." : ""}
                {result.failed.length ? " Failed " + result.failed.length + "." : ""}
              </div>
            ) : null}

            <input className="inv-search" placeholder="Filter by IP, hostname, model, rack…"
                   value={filter} onChange={function(e){ setFilter(e.target.value); }} />

            <div style={{display:"flex", alignItems:"center", gap:8, margin:"6px 0"}}>
              <button type="button" className="secondary small"
                      onClick={function(){
                        setSel(function(p){
                          const n = Object.assign({}, p);
                          shown.forEach(function(r){
                            if (!r.already_added) n[r.ilo_ip] = true;
                          });
                          return n;
                        });
                      }}>
                <i className="uil uil-check-square" /> Select all
                {filter ? " shown" : ""} ({shown.filter(function(r){ return !r.already_added; }).length})
              </button>
              <button type="button" className="secondary small"
                      onClick={function(){ setSel({}); }}>
                Clear
              </button>
              <span className="muted small" style={{marginLeft:"auto"}}>
                {chosen.length} selected — one password will unlock all of them
              </span>
            </div>

            <div className="inv-list">
              {shown.map(function(r){
                return (
                  <label key={r.ilo_ip}
                         className={cls("inv-row", r.already_added && "disabled",
                                        sel[r.ilo_ip] && "sel")}>
                    <input type="checkbox" disabled={r.already_added}
                           checked={!!sel[r.ilo_ip]}
                           onChange={function(){ toggle(r.ilo_ip); }} />
                    <div className="inv-main">
                      <div className="inv-ip">{r.ilo_ip}
                        {r.gpu_model ? <span className="pill ok" style={{marginLeft:8}}
                          title={"GPU node · owner " + (r.owner || "?") +
                                 (r.lm ? " · LM " + r.lm : "")}>
                          {r.gpu_model}</span> : null}
                        {r.already_added ? <span className="pill" style={{marginLeft:8}}>added</span> : null}

                      </div>
                      <div className="inv-meta">
                        {[r.owner, r.team, r.hostname, r.model,
                          r.rack ? "Rack " + r.rack : "", r.solution]
                          .filter(Boolean).join(" · ")}
                      </div>
                      {r.note ? <div className="inv-note">{r.note}</div> : null}
                    </div>
                  </label>
                );
              })}
              {shown.length === 0 ? <div className="muted small">No matches.</div> : null}
            </div>

            <div className="inv-creds">
              <div className="row two">
                <label><div className="label-text">iLO username</div>
                  <input value={creds.username} autoComplete="off"
                         onChange={function(e){ const v=e.target.value; setCreds(function(p){return Object.assign({},p,{username:v});}); }} />
                </label>
                <label><div className="label-text">iLO password</div>
                  <input type="password" value={creds.password} autoComplete="off"
                         onChange={function(e){ const v=e.target.value; setCreds(function(p){return Object.assign({},p,{password:v});}); }} />
                </label>
              </div>
              <div className="muted small">
                One password unlocks every selected server, the same as
                unlocking a switch. No credentials are ever stored in the
                inventory — you enter them each time you add servers.
              </div>
            </div>

            {/* ── Bulk import ────────────────────────────────────────── */}
            <div className="bulk-block">
              <div className="row" style={{alignItems:"center", gap:8}}>
                <button type="button" className="secondary small" disabled={upBusy}
                        onClick={function(){ if (fileRef.current) fileRef.current.click(); }}>
                  <i className="uil uil-import" /> {upBusy ? "Reading…" : "Import from spreadsheet"}
                </button>
                <input ref={fileRef} type="file" style={{display:"none"}}
                       accept=".csv,.xlsx,.xls"
                       onChange={onFilePicked} />
                <span className="muted small">
                  CSV or Excel with a column of iLO addresses.
                </span>
              </div>

              {upErr ? <div className="alert error" style={{marginTop:8}}>{upErr}</div> : null}

              {bulkRes ? (
                <div className="alert ok" style={{marginTop:8}}>
                  Added {bulkRes.added_count} server{bulkRes.added_count === 1 ? "" : "s"} from{" "}
                  <b>{bulkRes.filename}</b>.
                  {bulkRes.unreachable_count
                    ? " " + bulkRes.unreachable_count + " added but did not answer — check credentials."
                    : ""}
                  {bulkRes.skipped && bulkRes.skipped.length ? " " + bulkRes.skipped.length + " already present." : ""}
                  {bulkRes.failed && bulkRes.failed.length ? " " + bulkRes.failed.length + " failed." : ""}
                </div>
              ) : null}

              {preview ? (
                <div className="bulk-preview" style={{marginTop:8}}>
                  <div className="small">
                    <b>{preview.filename}</b> — {preview.parsed} address
                    {preview.parsed === 1 ? "" : "es"} found,{" "}
                    <b>{preview.new}</b> new
                    {preview.already_added ? ", " + preview.already_added + " already added" : ""}
                    {preview.had_header ? " (header row skipped)" : ""}
                  </div>
                  {(preview.warnings || []).map(function(w, i){
                    return <div className="muted small" key={i}>• {w}</div>;
                  })}
                  <div className="bulk-rows small" style={{maxHeight:160, overflowY:"auto", marginTop:6}}>
                    {(preview.rows || []).map(function(r, i){
                      return (
                        <div key={i} className={r.status === "new" ? "" : "muted"}>
                          {r.host} — {r.status}
                        </div>
                      );
                    })}
                  </div>
                  {preview.needs_credentials && !(creds.username && creds.password) ? (
                    <div className="alert warn" style={{marginTop:6}}>
                      {preview.needs_credentials} row(s) have no credentials of their
                      own — fill in the iLO username and password above first.
                    </div>
                  ) : null}
                  <div style={{marginTop:8}}>
                    <button type="button" className="primary small"
                            onClick={commitUpload}
                            disabled={upBusy || preview.new === 0 ||
                              (preview.needs_credentials > 0 && !(creds.username && creds.password))}>
                      {upBusy ? "Adding…" : "Import " + preview.new + " server" +
                        (preview.new === 1 ? "" : "s")}
                    </button>
                  </div>
                </div>
              ) : null}
            </div>

            {err ? <div className="alert error">{err}</div> : null}
            <div className="modal-actions">
              <button type="button" className="secondary" onClick={onClose}>Close</button>
              <button type="submit" className="primary" disabled={busy || !chosen.length}>
                {busy ? "Adding…" : "Add " + (chosen.length || "") + " server" + (chosen.length === 1 ? "" : "s")}
              </button>
            </div>
          </form>
        ) : (
          <form className="modal-body" onSubmit={saveManual}>
            <div className="row two">
              <label><div className="label-text">Name</div>
                <input value={form.name} autoFocus
                       onChange={function(e){ const v=e.target.value; setForm(function(p){return Object.assign({},p,{name:v});}); }} />
              </label>
              <label><div className="label-text">Host / IP</div>
                <input value={form.host} placeholder="10.25.51.143"
                       onChange={function(e){ const v=e.target.value; setForm(function(p){return Object.assign({},p,{host:v});}); }} />
              </label>
            </div>
            <div className="row two">
              <label><div className="label-text">Username</div>
                <input value={form.username} autoComplete="off"
                       onChange={function(e){ const v=e.target.value; setForm(function(p){return Object.assign({},p,{username:v});}); }} />
              </label>
              <label><div className="label-text">Password</div>
                <input type="password" value={form.password} autoComplete="off"
                       onChange={function(e){ const v=e.target.value; setForm(function(p){return Object.assign({},p,{password:v});}); }} />
              </label>
            </div>
            <label><div className="label-text">Location (optional)</div>
              <input value={form.location}
                     onChange={function(e){ const v=e.target.value; setForm(function(p){return Object.assign({},p,{location:v});}); }} />
            </label>
            <div className="muted small">
              The portal detects how to read this server automatically — iLO
              Redfish first, then SSH — and streams real metrics about a second
              later. Nothing is simulated.
            </div>
            {err ? <div className="alert error">{err}</div> : null}
            <div className="modal-actions">
              <button type="button" className="secondary" onClick={onClose}>Cancel</button>
              <button type="submit" className="primary" disabled={busy}>
                {busy ? "Detecting…" : "Add server"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function ServerMonitorPanel(props) {
  const server = props.server;
  const onDeleted = props.onDeleted;

  const [sensors, setSensors]   = useState([]);
  const [sensor, setSensor]     = useState("cpu_utilization");
  const [range, setRange]       = useState("10min");
  const [data, setData]         = useState(null);
  const [latestAll, setLatestAll] = useState(null);   // Performance Data section
  const [alerts, setAlerts]     = useState({ lower_threshold: 0, lower_dwell_sec: 0,
                                             upper_threshold: 0, upper_dwell_sec: 0 });
  const [alertMsg, setAlertMsg] = useState("");
  const [err, setErr]           = useState("");
  const [liveAt, setLiveAt]     = useState(null);   // last SSE frame time

  // Sensor list (once per server)
  useEffect(function() {
    let alive = true;
    api("/api/servers/" + encodeURIComponent(server.name) + "/sensors")
      .then(function(s){ if (alive) setSensors(s); })
      .catch(function(e){ if (alive) setErr(e.message); });
    return function(){ alive = false; };
  }, [server.name]);

  // Metric history — refetch on sensor/range change + poll every 20s
  const loadMetrics = useCallback(function() {
    api("/api/servers/" + encodeURIComponent(server.name) +
        "/metrics?sensor=" + encodeURIComponent(sensor) +
        "&range_key=" + encodeURIComponent(range))
      .then(function(d){ setData(d); setErr(""); })
      .catch(function(e){ setErr(e.message); });
  }, [server.name, sensor, range]);

  useEffect(function() {
    loadMetrics();                       // history for the selected range
    const t = setInterval(loadMetrics, 120000);  // safety re-sync only;
    return function(){ clearInterval(t); };      // live points arrive via SSE
  }, [loadMetrics]);

  // LIVE: Server-Sent Events push each new real sample the moment it lands,
  // so the graph moves without waiting for the 20s refetch.
  useEffect(function() {
    if (!window.EventSource) return;
    const url = API + "/api/servers/" + encodeURIComponent(server.name) +
                "/stream?sensor=" + encodeURIComponent(sensor);
    const es = new EventSource(url);
    es.onmessage = function(ev) {
      try {
        const p = JSON.parse(ev.data);
        setLiveAt(Date.now());
        setData(function(prev) {
          if (!prev) return prev;
          const pts = prev.points.concat([{ t: p.t, v: p.v }]);
          return Object.assign({}, prev, {
            points: pts.slice(-600),
            latest: p.v, latest_at: p.t, source: p.source || prev.source,
          });
        });
      } catch (e) { /* ignore malformed frame */ }
    };
    es.onerror = function(){ /* browser auto-reconnects */ };
    return function(){ es.close(); };
  }, [server.name, sensor]);

  // Performance Data: latest value of EVERY sensor (poll every 20s)
  const loadLatestAll = useCallback(function() {
    Promise.all((sensors.length ? sensors : []).map(function(s) {
      return api("/api/servers/" + encodeURIComponent(server.name) +
                 "/metrics?sensor=" + s.key + "&range_key=10min")
        .then(function(d){ return { key: s.key, label: s.label, unit: s.unit,
                                    v: d.latest, t: d.latest_at }; })
        .catch(function(){ return { key: s.key, label: s.label, unit: s.unit, v: null }; });
    })).then(setLatestAll);
  }, [server.name, sensors]);

  useEffect(function() {
    if (!sensors.length) return;
    loadLatestAll();
    const t = setInterval(loadLatestAll, 10000);
    return function(){ clearInterval(t); };
  }, [sensors, loadLatestAll]);

  // Alert settings for current sensor
  useEffect(function() {
    let alive = true;
    api("/api/servers/" + encodeURIComponent(server.name) +
        "/alert-settings?sensor=" + encodeURIComponent(sensor))
      .then(function(a){ if (alive) setAlerts(a); })
      .catch(function(){ /* defaults ok */ });
    setAlertMsg("");
    return function(){ alive = false; };
  }, [server.name, sensor]);

  async function applyAlerts() {
    setAlertMsg("");
    try {
      await api("/api/servers/" + encodeURIComponent(server.name) + "/alert-settings", {
        method: "PUT",
        body: JSON.stringify({
          sensor: sensor,
          lower_threshold: Number(alerts.lower_threshold) || 0,
          lower_dwell_sec: Number(alerts.lower_dwell_sec) || 0,
          upper_threshold: Number(alerts.upper_threshold) || 0,
          upper_dwell_sec: Number(alerts.upper_dwell_sec) || 0,
        }),
      });
      setAlertMsg("Saved. Threshold state updates within a few seconds.");
    } catch (e) { setAlertMsg("Error: " + e.message); }
  }

  async function removeServer() {
    if (!confirm("Delete server '" + server.name + "' and all its metrics?")) return;
    try {
      await api("/api/servers/" + encodeURIComponent(server.name), { method: "DELETE" });
      onDeleted(server.name);
    } catch (e) { setErr(e.message); }
  }

  function updAlert(k, v) {
    setAlerts(function(p){ const n = Object.assign({}, p); n[k] = v; return n; });
  }

  const sensorLabel = (sensors.find(function(s){ return s.key === sensor; }) || {}).label || sensor;
  const rangeMeta = ILO_RANGES.find(function(r){ return r.key === range; }) || ILO_RANGES[0];
  const latest = data && data.latest != null ? data.latest : "—";
  const latestAt = data && data.latest_at ? new Date(data.latest_at) : null;

  return (
    <div className="panel ilo-panel">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-server" />
          <div>
            <div className="panel-title">Performance – Monitoring</div>
            <div className="panel-sub">
              {server.name} · iLO {server.ilo_host}
              {server.last_source === "redfish" ? (
                <span className="pill ok" style={{marginLeft:8}}>live · iLO Redfish</span>
              ) : null}
              {server.last_source === "ssh" ? (
                <span className="pill ok" style={{marginLeft:8}}>live · SSH /proc</span>
              ) : null}
              {server.last_source === "simulated" ? (
                <span className="pill warn" style={{marginLeft:8}}
                      title={server.last_poll_error}>SIMULATED</span>
              ) : null}
              {server.last_poll_status === "error" ? (
                <span className="pill err" style={{marginLeft:8}}
                      title={server.last_poll_error}>no real data</span>
              ) : null}
              <span className={cls("pill", liveAt && (Date.now() - liveAt < 5000) ? "live" : "")}
                    style={{marginLeft:8}}
                    title={liveAt ? "streaming ~1 sample/sec" : "waiting for first sample"}>
                <i className="uil uil-signal-alt-3" />{" "}
                {liveAt ? "live · 1 Hz" : "connecting…"}
              </span>
            </div>
          </div>
        </div>
        <div className="panel-id-right">
          <button className="secondary small" onClick={props.onEdit}>
            <i className="uil uil-edit" /> Edit
          </button>
          <button className="danger small" onClick={removeServer}>
            <i className="uil uil-trash-alt" /> Remove
          </button>
        </div>
      </div>

      {err ? <div className="alert error">{err}</div> : null}
      {props.alert && props.alert.state === "breach" ? (
        <div className="alert error breach-banner">
          <i className="uil uil-exclamation-octagon" />{" "}
          <strong>Threshold breached:</strong>{" "}
          {props.alert.breaches.map(function(b){
            return b.sensor.replace(/_/g," ") + " is " + b.value + b.unit +
                   " (" + (b.kind === "upper" ? "above" : "below") + " " +
                   b.threshold + " for " + b.dwell_sec + "s)";
          }).join("; ")}
        </div>
      ) : null}

      {/* Sensor picker + iLO range buttons */}
      <div className="ilo-controls">
        <label className="ilo-sensor-box">
          <div className="ilo-sensor-label">Selected Sensor</div>
          <select value={sensor} onChange={function(e){ setSensor(e.target.value); }}>
            {sensors.map(function(s){
              return <option key={s.key} value={s.key}>{s.label}</option>;
            })}
          </select>
        </label>
        <div className="ilo-ranges">
          {ILO_RANGES.map(function(r){
            return (
              <button key={r.key}
                      className={cls("ilo-range", range === r.key && "active")}
                      onClick={function(){ setRange(r.key); }}>
                {r.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* History graph */}
      <div className="ilo-section">
        <div className="ilo-h2">
          {rangeMeta.label === "10 min" ? "10-Minute" :
           rangeMeta.label === "1 hr"   ? "1-Hour" :
           rangeMeta.label === "24 hr"  ? "24-Hour" : "1-Week"} History Graph
          {" "}
          <button className="icon-btn" title="Refresh" onClick={loadMetrics}>
            <i className="uil uil-sync" />
          </button>
        </div>
        <div className="ilo-sub">
          {sensorLabel} over the past {rangeMeta.sub} at {rangeMeta.tick}.
        </div>
        <div className="ilo-chart-row">
          <IloChart points={data ? data.points : []} unit={data ? data.unit : "%"} />
          <div className="ilo-legend">
            <div className="ilo-legend-key">
              <span className="ilo-swatch" /> Utilization
              <span className="ilo-legend-value">{latest}</span>
            </div>
            {latestAt ? (
              <div className="ilo-legend-time">
                {latestAt.getFullYear()}-{("0"+(latestAt.getMonth()+1)).slice(-2)}-{("0"+latestAt.getDate()).slice(-2)}
                <br />
                {("0"+latestAt.getHours()).slice(-2)}:{("0"+latestAt.getMinutes()).slice(-2)}:{("0"+latestAt.getSeconds()).slice(-2)}
              </div>
            ) : null}
            {data ? <div className="ilo-legend-unit">(in {data.unit})</div> : null}
          </div>
        </div>
      </div>

      {/* Alert Settings */}
      <div className="ilo-section">
        <div className="ilo-h2">Alert Settings – {sensorLabel}</div>
        <div className="ilo-alert-grid">
          <label><div className="ilo-alert-label">Lower Threshold (in %)</div>
            <input type="number" value={alerts.lower_threshold}
                   onChange={function(e){ updAlert("lower_threshold", e.target.value); }} />
          </label>
          <label><div className="ilo-alert-label">Dwell Time (in sec)</div>
            <input type="number" value={alerts.lower_dwell_sec}
                   onChange={function(e){ updAlert("lower_dwell_sec", e.target.value); }} />
          </label>
          <label><div className="ilo-alert-label">Upper Threshold (in %)</div>
            <input type="number" value={alerts.upper_threshold}
                   onChange={function(e){ updAlert("upper_threshold", e.target.value); }} />
          </label>
          <label><div className="ilo-alert-label">Dwell Time (in sec)</div>
            <input type="number" value={alerts.upper_dwell_sec}
                   onChange={function(e){ updAlert("upper_dwell_sec", e.target.value); }} />
          </label>
        </div>
        <div style={{display:"flex", alignItems:"center", gap:12, marginTop:12}}>
          <button className="ilo-apply" onClick={applyAlerts}>Apply</button>
          {alertMsg ? <span className="muted small">{alertMsg}</span> : null}
        </div>
      </div>

      {/* Performance Data */}
      <div className="ilo-section">
        <div className="ilo-h2">Performance Data</div>
        <table className="table">
          <thead>
            <tr><th>Sensor</th><th>Latest value</th><th>Unit</th><th>As of</th></tr>
          </thead>
          <tbody>
            {(latestAll || []).map(function(row){
              return (
                <tr key={row.key}
                    className={row.key === sensor ? "ilo-row-active" : ""}
                    style={{cursor:"pointer"}}
                    onClick={function(){ setSensor(row.key); }}>
                  <td>{row.label}</td>
                  <td>{row.v != null ? row.v : "—"}</td>
                  <td>{row.unit}</td>
                  <td>{row.t ? new Date(row.t).toLocaleTimeString() : "—"}</td>
                </tr>
              );
            })}
            {!latestAll ? (
              <tr><td colSpan="4" className="muted">Loading…</td></tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EditDialog(props) {
  // kind: "switch" | "server"
  const kind = props.kind, item = props.item;
  const onClose = props.onClose, onSaved = props.onSaved;
  const isSwitch = kind === "switch";

  const [form, setForm] = useState(
    isSwitch
      ? { name:item.name, host:item.host, port:item.port || 22,
          device_type:item.device_type, location:item.location || "" }
      : { name:item.name, ilo_host:item.ilo_host, location:item.location || "",
          description:item.description || "" }
  );
  const [creds, setCreds] = useState({ username:"", password:"" });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  function upd(k,v){ setForm(function(p){ const n=Object.assign({},p); n[k]=v; return n; }); }

  async function save(e){
    if (e) e.preventDefault();
    setErr("");
    if (!form.name) { setErr("Name is required."); return; }
    setBusy(true);
    try {
      const body = Object.assign({}, form);
      if (isSwitch && form.port) body.port = Number(form.port);
      // Credentials are optional — only sent if you want to rotate them.
      if (creds.username) body.username = creds.username;
      if (creds.password) body.password = creds.password;

      const url = isSwitch
        ? "/api/switches/" + encodeURIComponent(item.name)
        : "/api/servers/" + encodeURIComponent(item.name) + "/edit";
      await api(url, { method:"PATCH", body: JSON.stringify(body) });
      onSaved(form.name);
    } catch (e2) { setErr(e2.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={function(e){ e.stopPropagation(); }}>
        <div className="modal-head">
          <i className="uil uil-edit" />
          <div>
            <div className="modal-title">Edit {isSwitch ? "switch" : "server"}</div>
            <div className="modal-sub">{item.name}</div>
          </div>
          <button className="icon-btn" onClick={onClose}><i className="uil uil-times" /></button>
        </div>
        <form className="modal-body" onSubmit={save}>
          <div className="row two">
            <label><div className="label-text">Name</div>
              <input value={form.name} autoFocus
                     onChange={function(e){ upd("name", e.target.value); }} />
            </label>
            <label><div className="label-text">{isSwitch ? "Host / IP" : "iLO host / IP"}</div>
              <input value={isSwitch ? form.host : form.ilo_host}
                     onChange={function(e){ upd(isSwitch ? "host" : "ilo_host", e.target.value); }} />
            </label>
          </div>

          {isSwitch ? (
            <div className="row two">
              <label><div className="label-text">SSH port</div>
                <input type="number" value={form.port}
                       onChange={function(e){ upd("port", e.target.value); }} />
              </label>
              <label><div className="label-text">Device type</div>
                <select value={form.device_type}
                        onChange={function(e){ upd("device_type", e.target.value); }}>
                  <option value="hp_comware">HP Comware</option>
                  <option value="aruba_aoscx">Aruba AOS-CX</option>
                  <option value="aruba_procurve">Aruba ProCurve / ProVision</option>
                </select>
              </label>
            </div>
          ) : (
            <label><div className="label-text">Description</div>
              <input value={form.description}
                     onChange={function(e){ upd("description", e.target.value); }} />
            </label>
          )}

          <label><div className="label-text">Location</div>
            <input value={form.location}
                   onChange={function(e){ upd("location", e.target.value); }} />
          </label>

          <div className="form-divider">Rotate credentials (optional)</div>
          <div className="row two">
            <label><div className="label-text">Username</div>
              <input value={creds.username} autoComplete="off" placeholder="leave blank to keep"
                     onChange={function(e){ const v=e.target.value; setCreds(function(p){return Object.assign({},p,{username:v});}); }} />
            </label>
            <label><div className="label-text">Password</div>
              <input type="password" value={creds.password} autoComplete="off" placeholder="leave blank to keep"
                     onChange={function(e){ const v=e.target.value; setCreds(function(p){return Object.assign({},p,{password:v});}); }} />
            </label>
          </div>

          {err ? <div className="alert error">{err}</div> : null}
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="primary" disabled={busy}>
              {busy ? "Saving…" : "Save changes"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════
// LACP CONFIGURATION — one-click link aggregation between two switches.
// Backed by /api/lacp/preflight (five live validations + generated CLI),
// /api/lacp/deploy (checkpointed, rolled back on failure), and
// /api/lacp/deployments (live progress polling + history).
// ════════════════════════════════════════════════════════════════════

// Member picker for one side: checkbox list of physical ports with filter.
function LacpMemberPicker(props) {
  const sw = props.switchName;
  const [ports, setPorts]   = useState(null);
  const [filter, setFilter] = useState("");
  const [err, setErr]       = useState("");

  useEffect(function() {
    setPorts(null); setErr("");
    if (!sw) return;
    api("/api/port-stats/latest?switch_name=" + encodeURIComponent(sw))
      .then(function(d){
        const phys = (d.ports || []).filter(function(p){
          return !/^(bridge-agg|bagg|lag|route-agg|ragg|vlan|mgmt|loop|null|inloop|reg)/i
            .test(p.interface);
        });
        setPorts(phys);
      })
      .catch(function(e){ setErr(e.message); });
  }, [sw]);

  const selected = props.selected;
  function toggle(name){
    const next = selected.indexOf(name) >= 0
      ? selected.filter(function(x){ return x !== name; })
      : selected.concat([name]);
    props.onChange(next);
  }

  if (!sw) return <div className="muted small">Select a switch first.</div>;
  if (err) return <div className="alert error">{err}</div>;
  if (ports === null) return <div className="muted small">Loading ports…</div>;
  if (!ports.length) {
    return (
      <div className="muted small">
        No port data — run a port-stats capture for {sw} first
        (Switches → {sw} → Port stats).
      </div>
    );
  }

  const shown = ports.filter(function(p){
    if (!filter) return true;
    const f = filter.toLowerCase();
    return p.interface.toLowerCase().indexOf(f) >= 0 ||
           (p.port_description || "").toLowerCase().indexOf(f) >= 0;
  });

  return (
    <div>
      <div style={{display:"flex", gap:6, marginBottom:6}}>
        <input type="text" placeholder="filter ports…" value={filter}
               style={{flex:1}}
               onChange={function(e){ setFilter(e.target.value); }} />
        <button className="secondary small" type="button"
                onClick={function(){ props.onChange([]); }}>Clear</button>
      </div>
      <div className="lacp-portlist">
        {shown.map(function(p){
          const on = selected.indexOf(p.interface) >= 0;
          return (
            <label key={p.interface}
                   className={cls("lacp-port", on && "sel")}>
              <input type="checkbox" checked={on}
                     onChange={function(){ toggle(p.interface); }} />
              <code>{p.interface}</code>
              <span className={"pill " + (/up/i.test(p.link_state) ? "ok" : "")}>
                {p.link_state || "?"}
              </span>
              <span className="muted small lacp-port-desc">
                {p.port_description || ""}
              </span>
            </label>
          );
        })}
        {!shown.length ? <div className="muted small" style={{padding:6}}>
          no ports match the filter</div> : null}
      </div>
      <div className="muted small" style={{marginTop:4}}>
        {selected.length} selected
        {selected.length ? ": " + selected.join(", ") : ""}
      </div>
    </div>
  );
}

function LacpChecks(props) {
  // props.results: [{switch, role, mode, ok, checks:[{name,status,detail}], cli}]
  return (
    <div>
      {props.results.map(function(r){
        return (
          <div key={r.switch} className="lacp-checkblock">
            <div className="lacp-checkhead">
              <strong>{r.switch}</strong>
              <span className="pill">{r.role}</span>
              <span className="pill">{r.mode}</span>
              <span className={"pill " + (r.ok ? "ok" : "err")}>
                {r.ok ? "all checks passed" : "violations"}
              </span>
            </div>
            {(r.checks || []).map(function(c, i){
              return (
                <div key={i} className={"lacp-check " + c.status}>
                  <i className={"uil " + (c.status === "pass"
                      ? "uil-check-circle"
                      : c.status === "warn" ? "uil-exclamation-triangle"
                      : "uil-times-circle")} />
                  <span className="lacp-check-name">{c.name}</span>
                  <span className="muted small">{c.detail}</span>
                </div>
              );
            })}
            {r.cli && r.cli.length ? (
              <details className="lacp-cli">
                <summary className="muted small">
                  Generated CLI ({r.cli.length} lines)
                </summary>
                <pre>{r.cli.join("\n")}</pre>
              </details>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function LacpProgress(props) {
  const dep = props.dep;   // deployment object from the poll
  if (!dep) return null;
  const running = dep.status === "running";
  return (
    <div className="lacp-progress">
      <div className="lacp-checkhead">
        <strong>Deployment #{dep.id}</strong>
        <span className={"pill " + (dep.status === "completed" ? "ok"
              : running ? "live" : "err")}>{dep.status}</span>
        {dep.duration_sec ? <span className="muted small">
          {dep.duration_sec}s</span> : null}
      </div>
      {(dep.steps || []).map(function(s, i){
        return (
          <div key={i} className={"lacp-step " + s.status}>
            <i className={"uil " + (s.status === "done" ? "uil-check"
                : s.status === "running" ? "uil-spinner-alt"
                : "uil-times")} />
            <span>
              {s.switch ? <strong>{s.switch}: </strong> : null}
              {s.stage}{s.status === "running" ? "…" : ""}
            </span>
            {s.detail ? <span className="muted small"> — {s.detail}</span> : null}
          </div>
        );
      })}
      {dep.error ? <div className="alert error" style={{marginTop:8}}>
        {dep.error}</div> : null}

      {dep.verification && Object.keys(dep.verification).length ? (
        <div style={{marginTop:10}}>
          <div className="ilo-h2">Post-deployment verification</div>
          {Object.keys(dep.verification).map(function(swName){
            const v = dep.verification[swName] || {};
            if (v.error) {
              return <div key={swName} className="alert error">
                {swName}: {v.error}</div>;
            }
            return (
              <div key={swName} className="lacp-verify">
                <div className="lacp-checkhead">
                  <strong>{swName}</strong>
                  <span className="pill">LAG {v.lag_id}</span>
                  <span className={"pill " + (v.lag_present ? "ok" : "err")}>
                    {v.lag_present ? "LAG present" : "LAG missing"}
                  </span>
                  <span className={"pill " + (v.operational ? "ok" : "warn")}>
                    {v.operational ? "operational · in sync"
                                   : "not fully synchronized"}
                  </span>
                </div>
                {(v.members || []).map(function(m, i){
                  return (
                    <div key={i} className="lacp-check pass">
                      <code>{m.interface}</code>
                      <span className="pill">{m.state}</span>
                      <span className={"pill " + (m.sync === "in-sync" ? "ok" : "warn")}>
                        {m.sync}
                      </span>
                    </div>
                  );
                })}
                {(v.missing_members || []).length ? (
                  <div className="alert error" style={{marginTop:4}}>
                    missing from the bundle: {v.missing_members.join(", ")}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function LacpHistory(props) {
  const [rows, setRows]   = useState([]);
  const [openId, setOpen] = useState(0);
  const [detail, setDetail] = useState(null);

  const load = useCallback(function(){
    api("/api/lacp/deployments?limit=50")
      .then(setRows).catch(function(){});
  }, []);
  useEffect(function(){
    load();
    const t = setInterval(load, 10000);
    return function(){ clearInterval(t); };
  }, [load, props.bump]);

  function expand(id){
    if (openId === id) { setOpen(0); setDetail(null); return; }
    setOpen(id); setDetail(null);
    api("/api/lacp/deployments/" + id).then(setDetail).catch(function(){});
  }

  return (
    <div className="panel" style={{marginTop:14}}>
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-history" />
          <div>
            <div className="panel-title">Deployment history</div>
            <div className="panel-sub">
              Every LACP run — who, when, which switches, which LAG, how it
              ended and how long it took. Click a row for its full log.
            </div>
          </div>
        </div>
      </div>
      {!rows.length ? (
        <div className="muted small" style={{padding:"0 16px 14px"}}>
          No deployments yet.
        </div>
      ) : (
        <table className="lacp-history">
          <thead>
            <tr><th>Time</th><th>User</th><th>Switches</th><th>LAG</th>
                <th>Mode</th><th>Status</th><th>Duration</th></tr>
          </thead>
          <tbody>
            {rows.map(function(r){
              return (
                <React.Fragment key={r.id}>
                  <tr className="lacp-history-row"
                      onClick={function(){ expand(r.id); }}>
                    <td>{r.created_at ? new Date(r.created_at).toLocaleString() : ""}</td>
                    <td>{r.user}</td>
                    <td>{r.source_switch}{r.dest_switch ? " ↔ " + r.dest_switch : ""}</td>
                    <td>LAG {r.lag_id}</td>
                    <td>{r.lacp_mode}</td>
                    <td><span className={"pill " + (r.status === "completed" ? "ok"
                        : r.status === "running" ? "live" : "err")}>{r.status}</span></td>
                    <td>{r.duration_sec ? r.duration_sec + "s" : "—"}</td>
                  </tr>
                  {openId === r.id ? (
                    <tr><td colSpan={7}>
                      {!detail ? <div className="muted small">loading…</div> : (
                        <div>
                          {detail.error ? <div className="alert error">
                            {detail.error}</div> : null}
                          <LacpProgress dep={detail} />
                          {detail.logs ? (
                            <details className="lacp-cli">
                              <summary className="muted small">
                                Full command log
                              </summary>
                              <pre>{detail.logs}</pre>
                            </details>
                          ) : null}
                        </div>
                      )}
                    </td></tr>
                  ) : null}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function LacpConfigView(props) {
  const switches = props.switches || [];
  const [srcSw, setSrcSw]   = useState("");
  const [dstSw, setDstSw]   = useState("");
  const [lagId, setLagId]   = useState("");
  const [mode, setMode]     = useState("active");
  const [speed, setSpeed]   = useState("auto");
  const [descr, setDescr]   = useState("");
  const [members, setMembers] = useState({});   // {switch: [ifaces]}

  const [gate, setGate]         = useState(null);
  const [execInfo, setExecInfo] = useState(null);
  const [applyToken, setToken]  = useState("");
  const [checking, setChecking] = useState(false);
  const [pre, setPre]           = useState(null);
  const [confirm, setConfirm]   = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [dep, setDep]           = useState(null);
  const [err, setErr]           = useState("");
  const [histBump, setHistBump] = useState(0);
  const pollRef = React.useRef(null);

  useEffect(function(){
    api("/api/config/status").then(setGate).catch(function(){});
    api("/api/lacp/exec-status").then(setExecInfo).catch(function(){});
    return function(){ if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  function setSideMembers(sw){
    return function(list){
      setMembers(function(m){
        const next = Object.assign({}, m);
        next[sw] = list;
        return next;
      });
      setPre(null);            // selection changed — validation is stale
    };
  }

  function payload(){
    const body = {
      source_switch: srcSw, dest_switch: dstSw,
      lag_id: parseInt(lagId, 10),
      lacp_mode: mode, speed: speed, description: descr,
      members: {},
    };
    body.members[srcSw] = members[srcSw] || [];
    body.members[dstSw] = members[dstSw] || [];
    return body;
  }

  const formOk = srcSw && dstSw && srcSw !== dstSw &&
    lagId && parseInt(lagId, 10) >= 1 &&
    (members[srcSw] || []).length && (members[dstSw] || []).length;

  async function runPreflight(){
    setChecking(true); setErr(""); setPre(null);
    try {
      const r = await api("/api/lacp/preflight",
        { method: "POST", body: JSON.stringify(payload()) }, srcSw);
      setPre(r);
    } catch(e){ setErr(e.message); }
    finally { setChecking(false); }
  }

  function startPolling(id){
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async function(){
      try {
        const d = await api("/api/lacp/deployments/" + id);
        setDep(d);
        if (d.status !== "running") {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setDeploying(false);
          setHistBump(function(x){ return x + 1; });
        }
      } catch(e){ /* keep polling */ }
    }, 1000);
  }

  async function deploy(){
    setConfirm(false); setErr(""); setDep(null); setDeploying(true);
    try {
      const headers = {};
      if (applyToken) headers["X-Apply-Token"] = applyToken;
      const r = await api("/api/lacp/deploy",
        { method: "POST", headers: headers,
          body: JSON.stringify(payload()) }, srcSw);
      setDep(r);
      startPolling(r.id);
    } catch(e){
      setErr(e.message);
      setDeploying(false);
    }
  }

  const applyEnabled = gate && gate.apply_enabled;

  return (
    <div style={{padding:14}}>
      <div className="panel">
        <div className="panel-head">
          <div className="panel-id">
            <i className="uil uil-sitemap" />
            <div>
              <div className="panel-title">LACP Configuration</div>
              <div className="panel-sub">
                One click replaces the whole manual sequence: pick the two
                switches and their member ports — the portal validates,
                checkpoints, configures both ends, saves, verifies the bundle
                and rolls back automatically if anything fails.
              </div>
            </div>
          </div>
        </div>

        {gate && !applyEnabled ? (
          <div className="alert" style={{margin:"0 16px 12px"}}>
            <i className="uil uil-lock" /> Configuration apply is disabled on
            the backend (CONFIG_APPLY_ENABLED=0). Validation and CLI preview
            work; Configure LACP will be refused until an admin enables the
            write path.
          </div>
        ) : null}

        {execInfo && execInfo.mode === "winrm" ? (
          <div className="alert" style={{margin:"0 16px 12px"}}>
            <i className="uil uil-windows" /> Changes are executed through the
            enterprise jump host <strong>{execInfo.jump_host}</strong> (WinRM →
            PowerShell → switch), the same path AD Studio uses for AD changes.
            {execInfo.jump_host_status ? (
              execInfo.jump_host_status.ok
                ? <span className="pill ok" style={{marginLeft:8}}>jump host reachable</span>
                : <span className="pill err" style={{marginLeft:8}}
                        title={execInfo.jump_host_status.detail}>
                    jump host unreachable</span>
            ) : null}
          </div>
        ) : null}

        <div className="lacp-form">
          <div className="lacp-form-grid">
            <label>Source switch
              <select value={srcSw}
                      onChange={function(e){ setSrcSw(e.target.value); setPre(null); }}>
                <option value="">— select —</option>
                {switches.map(function(s){
                  return <option key={s.name} value={s.name}
                                 disabled={s.name === dstSw}>
                    {s.name} ({s.device_type})</option>;
                })}
              </select>
            </label>
            <label>Destination switch
              <select value={dstSw}
                      onChange={function(e){ setDstSw(e.target.value); setPre(null); }}>
                <option value="">— select —</option>
                {switches.map(function(s){
                  return <option key={s.name} value={s.name}
                                 disabled={s.name === srcSw}>
                    {s.name} ({s.device_type})</option>;
                })}
              </select>
            </label>
            <label>LAG ID
              <input type="number" min="1" max="4096" value={lagId}
                     placeholder="e.g. 10"
                     onChange={function(e){ setLagId(e.target.value); setPre(null); }} />
            </label>
            <label>LACP mode
              <select value={mode}
                      onChange={function(e){ setMode(e.target.value); setPre(null); }}>
                <option value="active">Active</option>
                <option value="passive">Passive</option>
              </select>
            </label>
            <label>Interface speed
              <select value={speed}
                      onChange={function(e){ setSpeed(e.target.value); setPre(null); }}>
                {["auto","1G","10G","25G","40G","100G"].map(function(s){
                  return <option key={s} value={s}>{s}</option>;
                })}
              </select>
            </label>
            <label>Description (optional)
              <input type="text" value={descr} maxLength={200}
                     placeholder="e.g. uplink core-1 ↔ core-2 · gpu-node ilo101"
                     onChange={function(e){ setDescr(e.target.value); }} />
            </label>
          </div>
          {mode === "passive" ? (
            <div className="muted small" style={{marginTop:6}}>
              Passive applies to the source side; the destination is forced
              Active (passive + passive never negotiates a bundle).
            </div>
          ) : null}
        </div>

        <div className="lacp-members">
          <div className="lacp-member-col">
            <div className="ilo-h2">Member interfaces — {srcSw || "source"}</div>
            <LacpMemberPicker switchName={srcSw}
                              selected={members[srcSw] || []}
                              onChange={setSideMembers(srcSw)} />
          </div>
          <div className="lacp-member-col">
            <div className="ilo-h2">Member interfaces — {dstSw || "destination"}</div>
            <LacpMemberPicker switchName={dstSw}
                              selected={members[dstSw] || []}
                              onChange={setSideMembers(dstSw)} />
          </div>
        </div>

        {err ? <div className="alert error" style={{margin:"0 16px 12px"}}>{err}</div> : null}

        <div className="lacp-actions">
          <button className="secondary" disabled={!formOk || checking}
                  onClick={runPreflight}>
            <i className="uil uil-shield-check" />
            {checking ? " Validating…" : " Validate"}
          </button>
          <button className="primary"
                  disabled={!formOk || deploying || !(pre && pre.ok)}
                  title={!(pre && pre.ok)
                    ? "run Validate first — deploy is enabled once all checks pass"
                    : ""}
                  onClick={function(){ setConfirm(true); }}>
            <i className="uil uil-bolt" />
            {deploying ? " Deploying…" : " Configure LACP"}
          </button>
          {pre && !pre.ok ? (
            <span className="muted small">fix the failed checks below, then
              validate again</span>
          ) : null}
        </div>

        {pre ? (
          <div style={{padding:"0 16px 12px"}}>
            <div className="ilo-h2">Validation</div>
            {pre.note ? <div className="muted small" style={{marginBottom:6}}>
              {pre.note}</div> : null}
            <LacpChecks results={pre.results || []} />
          </div>
        ) : null}

        {dep ? (
          <div style={{padding:"0 16px 16px"}}>
            <div className="ilo-h2">Execution</div>
            <LacpProgress dep={dep} />
          </div>
        ) : null}
      </div>

      <LacpHistory bump={histBump} />

      {confirm ? (
        <div className="modal-backdrop" onClick={function(){ setConfirm(false); }}>
          <div className="modal" style={{maxWidth:520}}
               onClick={function(e){ e.stopPropagation(); }}>
            <h3><i className="uil uil-exclamation-triangle" /> Configure LACP</h3>
            <p className="muted">
              This writes to <strong>{srcSw}</strong> and <strong>{dstSw}</strong>:
              LAG {lagId} ({mode}) with{" "}
              {(members[srcSw] || []).length}+{(members[dstSw] || []).length} member
              ports. A checkpoint is taken on each switch first; any failure
              triggers automatic rollback on both ends.
            </p>
            {gate && gate.token_configured ? (
              <label style={{display:"block", marginBottom:10}}>Apply token
                <input type="password" value={applyToken}
                       placeholder="X-Apply-Token"
                       onChange={function(e){ setToken(e.target.value); }} />
              </label>
            ) : null}
            <div style={{display:"flex", gap:8, justifyContent:"flex-end"}}>
              <button className="secondary"
                      onClick={function(){ setConfirm(false); }}>Cancel</button>
              <button className="primary" onClick={deploy}>
                Deploy now
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}


// ── Link Insights — port-channel ↔ server correlation ───────────────
// Reads /api/link-insights: LAGs (and described ports) whose description
// names a server or its iLO last octet, joined with that server's live
// CPU / memory / jitter and an estimated CPU cost of the link's traffic.
function LinkInsightsView(props) {
  const [data, setData]   = useState(null);
  const [diag, setDiag]   = useState(null);
  const [swFilter, setSwFilter] = useState("");
  const [err, setErr]     = useState("");

  const load = useCallback(function(){
    const qs = swFilter ? "?switch_name=" + encodeURIComponent(swFilter) : "";
    api("/api/link-insights" + qs)
      .then(function(d){
        setData(d); setErr("");
        if (!(d.links || []).length) {
          // nothing matched — pull the diagnostic so we can say WHY
          api("/api/link-insights/diagnose" + qs)
            .then(setDiag).catch(function(){});
        } else {
          setDiag(null);
        }
      })
      .catch(function(e){ setErr(e.message); });
  }, [swFilter]);

  useEffect(function(){
    load();
    const t = setInterval(load, 10000);
    return function(){ clearInterval(t); };
  }, [load]);

  function metric(m, suffix){
    if (!m) return <span className="muted">—</span>;
    return (
      <span>
        <strong>{m.value}</strong>{m.unit || suffix || ""}
        {m.live ? <span className="pill live" style={{marginLeft:6}}
                        title="streamed from the iLO within the last few seconds">live</span>
                : m.stale ? <span className="pill warn" style={{marginLeft:6}}>stale</span> : null}
      </span>
    );
  }

  const links     = (data && data.links) || [];
  const unmatched = (data && data.unmatched) || [];

  function diagRow(ok, label, detail){
    return (
      <div className="lacp-check" style={{padding:"3px 2px"}}>
        <i className={"uil " + (ok ? "uil-check-circle" : "uil-times-circle")}
           style={{color: ok ? "var(--ok)" : "var(--err)"}} />
        <span className="lacp-check-name" style={{minWidth:210}}>{label}</span>
        <span className="muted small">{detail}</span>
      </div>
    );
  }

  return (
    <div style={{padding:14}}>
      <div className="panel">
        <div className="panel-head">
          <div className="panel-id">
            <i className="uil uil-link" />
            <div>
              <div className="panel-title">
                Link insights
                {links.length
                  ? <span className="pill ok" style={{marginLeft:8}}>
                      {links.length} matched link{links.length === 1 ? "" : "s"}
                    </span> : null}
              </div>
              <div className="panel-sub">
                Port-channels are matched to servers through their description
                (server name or iLO last octet). Each card pairs the port's
                packet rate with the server's live sensors, and estimates how
                much CPU and memory this link's transfers are costing — with the
                fit quality shown, so you know how much to trust it.
              </div>
            </div>
          </div>
          <select value={swFilter} style={{maxWidth:220}}
                  onChange={function(e){ setSwFilter(e.target.value); }}>
            <option value="">All switches</option>
            {(props.switches || []).map(function(s){
              return <option key={s.name} value={s.name}>{s.name}</option>;
            })}
          </select>
        </div>

        {err ? <div className="alert error">{err}</div> : null}

        {data && !links.length ? (
          <div style={{padding:"4px 16px 16px"}}>
            <div className="muted small" style={{marginBottom:10}}>
              No matched links yet. A match needs a registered server whose
              iLO last octet equals the number in a port's description. Here's
              what's present right now:
            </div>

            {diag ? (
              <div>
                {diagRow(diag.servers_registered > 0,
                  "Servers registered",
                  diag.servers_registered
                    ? diag.servers_registered + " server(s); iLO octets: " +
                      Object.keys(diag.server_ilo_octets || {}).join(", ")
                    : "none — add your servers in the Servers tab first, with "
                      + "iLO hosts like 10.25.51.161 for a 'VCF 161' port")}

                {(diag.switches || []).map(function(sd){
                  return (
                    <div key={sd.switch} className="lacp-checkblock"
                         style={{marginTop:10}}>
                      <div className="lacp-checkhead">
                        <strong>{sd.switch}</strong>
                        <span className={"pill " + (sd.matched ? "ok" : "warn")}>
                          {sd.matched} matched
                        </span>
                      </div>
                      {diagRow(sd.has_snapshot, "Config snapshot taken",
                        sd.has_snapshot ? "yes"
                          : "no — take a snapshot so descriptions can be read")}
                      {diagRow(sd.descriptions_found > 0, "Interface descriptions",
                        sd.descriptions_found + " found")}
                      {diagRow(sd.port_stats_captured > 0, "Port-stats captured",
                        sd.port_stats_captured
                          ? sd.port_stats_captured + " ports"
                          : "none — enable port-stats auto-capture (traffic "
                            + "estimate needs it; matching does not)")}

                      {sd.descriptions && sd.descriptions.length ? (
                        <details style={{marginTop:6}}>
                          <summary className="muted small">
                            {sd.descriptions.length} described interface(s) —
                            which numbers were found, and whether a server matched
                          </summary>
                          <table className="lacp-history" style={{marginTop:6}}>
                            <thead><tr><th>Interface</th><th>Description</th>
                              <th>Numbers</th><th>Matched server</th></tr></thead>
                            <tbody>
                              {sd.descriptions.map(function(d, i){
                                return (
                                  <tr key={i}>
                                    <td><code>{d.interface}</code></td>
                                    <td>{d.description}</td>
                                    <td>{(d.octets_in_description || []).join(", ") || "—"}</td>
                                    <td>{d.matched_server
                                      ? <span className="pill ok">{d.matched_server}</span>
                                      : <span className="muted">no server with that octet</span>}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </details>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="muted small">Checking…</div>
            )}
          </div>
        ) : null}

        {links.map(function(L){
          const at = L.attribution || {};
          const conf = at.r2 == null ? null
                     : at.r2 >= 0.5 ? "ok" : at.r2 >= 0.2 ? "warn" : "err";
          return (
            <div key={L.switch + "/" + L.interface} className="link-card">
              <div className="link-card-head">
                <div>
                  <strong>{L.interface}</strong>
                  {L.is_lag ? <span className="pill live" style={{marginLeft:6}}>LAG</span> : null}
                  <span className={"pill " + (/up/i.test(L.link_state) ? "ok" : "")}
                        style={{marginLeft:6}}>{L.link_state || "?"}</span>
                  <span className="muted small" style={{marginLeft:8}}>on {L.switch}</span>
                </div>
                <div className="muted small">“{L.description}”</div>
              </div>

              <div className="link-card-body">
                <div className="link-col">
                  <div className="link-col-title">
                    <i className="uil uil-database" /> {L.server}
                    <span className="muted small"> · iLO {L.server_ilo}</span>
                    <span className={"pill " + (L.match_basis === "octet" ? "warn" : "ok")}
                          style={{marginLeft:6}}
                          title={L.match_basis === "name"
                            ? "matched by server name in the description"
                            : L.match_basis === "label"
                              ? "matched by a labeled iLO octet (e.g. 'VCF 161')"
                              : L.match_basis === "ilo"
                                ? "matched by iLO octet marker in the description"
                                : "matched by a bare number token — verify this is right"}>
                      {L.match_basis} match
                    </span>
                  </div>
                  <div className="link-metrics">
                    <div>CPU {metric(L.server_metrics.cpu)}</div>
                    <div>Memory bus {metric(L.server_metrics.memory)}</div>
                    <div>Jitter {metric(L.server_metrics.jitter)}</div>
                  </div>
                </div>

                <div className="link-col">
                  <div className="link-col-title">
                    <i className="uil uil-chart-line" /> Traffic → load estimate
                  </div>
                  <div className="link-metrics">
                    <div>Current rate {at.current_pps != null
                      ? <span><strong>{at.current_pps}</strong> pps
                          {at.current_rate_human
                            ? <span className="muted"> · {at.current_rate_human}</span> : null}
                        </span>
                      : <span className="muted">—</span>}
                    </div>
                    {at.bytes_last_interval_human || at.bytes_window_human ? (
                      <div className="muted small">
                        Transferred: {at.bytes_last_interval_human || "—"}
                        {at.last_interval_sec ? " in last " + at.last_interval_sec + "s" : ""}
                        {at.bytes_window_human
                          ? " · " + at.bytes_window_human + " in last " +
                            (at.window_minutes || 60) + " min" : ""}
                      </div>
                    ) : null}
                    <div>Est. CPU from this link {at.estimated_cpu_pct != null
                      ? <span><strong>{at.estimated_cpu_pct}</strong>%
                          {at.r2 != null ? <span className={"pill " + conf}
                            style={{marginLeft:6}}>r² {at.r2}</span> : null}
                          {at.cpu_method === "active_vs_idle"
                            ? <span className="pill warn" style={{marginLeft:4}}
                                    title="regression saw no signal — this is the busy-vs-quiet CPU difference">busy vs quiet</span>
                            : null}
                        </span>
                      : <span className="muted">—</span>}
                    </div>
                    {at.cpu_cost_per_10kpps != null && at.cpu_cost_per_10kpps > 0 ? (
                      <div className="muted small">
                        ≈ {at.cpu_cost_per_10kpps}% CPU per 10k pps on this link
                      </div>
                    ) : null}
                    <div>Est. memory from this link {at.estimated_memory_pct != null
                      ? <span><strong>{at.estimated_memory_pct}</strong>%
                          {at.memory_r2 != null ? <span className={"pill " +
                            (at.memory_r2 >= 0.5 ? "ok" : at.memory_r2 >= 0.2 ? "warn" : "err")}
                            style={{marginLeft:6}}>r² {at.memory_r2}</span> : null}
                        </span>
                      : <span className="muted">—</span>}
                    </div>
                    {at.memory_cost_per_10kpps != null && at.memory_cost_per_10kpps > 0 ? (
                      <div className="muted small">
                        ≈ {at.memory_cost_per_10kpps}% memory per 10k pps
                      </div>
                    ) : null}
                    <div className="muted small">{at.points != null
                      ? at.points + " aligned samples" : ""}</div>
                  </div>
                  {at.note ? <div className="muted small" style={{marginTop:4}}>CPU: {at.note}</div> : null}
                  {at.memory_note ? <div className="muted small">Memory: {at.memory_note}</div> : null}
                </div>
              </div>
            </div>
          );
        })}

        {unmatched.length ? (
          <div style={{padding:"0 16px 14px"}}>
            <div className="ilo-h2">Described LAGs with no server match</div>
            {unmatched.map(function(u, i){
              return (
                <div key={i} className="muted small" style={{marginBottom:4}}>
                  <code>{u.interface}</code> on {u.switch} — “{u.description}”
                  · {u.hint}
                </div>
              );
            })}
          </div>
        ) : null}
      </div>
    </div>
  );
}

// ── Threshold Analysis — data-derived alert thresholds per server ───
// Runs the statistical baseline (mean/σ/percentiles over the metric history)
// and stores per-server upper/lower recommendations in the database.
// "Apply" copies a recommendation into the live alert settings.
function ThresholdAnalysisPanel(props) {
  const only = props && props.server ? props.server : "";
  const [rows, setRows]     = useState(null);
  const [running, setRun]   = useState(false);
  const [applying, setApplying] = useState("");
  const [windowH, setWindowH]   = useState(168);
  const [msg, setMsg]       = useState("");
  const [err, setErr]       = useState("");
  const [openRow, setOpenRow] = useState("");

  const load = useCallback(function(){
    api("/api/servers/thresholds")
      .then(function(d){
        let t = d.thresholds || [];
        if (only) t = t.filter(function(r){ return r.server === only; });
        setRows(t);
      })
      .catch(function(e){ setErr(e.message); });
  }, [only]);
  useEffect(function(){ load(); }, [load]);

  async function analyze(){
    setRun(true); setErr(""); setMsg("");
    try {
      const r = await api("/api/servers/thresholds/analyze",
        { method: "POST",
          body: JSON.stringify({ window_hours: parseInt(windowH, 10) || 168 }) });
      let m = "Analyzed " + r.analyzed + " server/sensor pair(s)";
      if (r.insufficient && r.insufficient.length) {
        const collecting = r.insufficient
          .filter(function(x){ return x.coverage_hours; })
          .map(function(x){ return x.server + " (" + x.coverage_hours +
                                   "h of 24h needed)"; });
        m += " · " + r.skipped + " still collecting" +
             (collecting.length ? ": " + collecting.slice(0,4).join(", ") +
              (collecting.length > 4 ? "…" : "") : "");
      }
      setMsg(m);
      load();
    } catch(e){ setErr(e.message); }
    finally { setRun(false); }
  }

  async function apply(server, sensor){
    const key = (server || "*") + "/" + (sensor || "*");
    setApplying(key); setErr(""); setMsg("");
    try {
      const r = await api("/api/servers/thresholds/apply",
        { method: "POST", body: JSON.stringify({ server: server, sensor: sensor }) });
      setMsg("Applied " + r.count + " threshold set(s) to live alert settings");
      load();
    } catch(e){ setErr(e.message); }
    finally { setApplying(""); }
  }

  function sensorLabel(s){
    return s === "cpu_utilization" ? "CPU"
         : s === "memory_bus_utilization" ? "Memory bus"
         : (s || "").replace(/_/g, " ");
  }

  return (
    <div className="panel srv-audits">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-chart-bar" />
          <div>
            <div className="panel-title">
              {only ? "Threshold analysis — " + only : "Threshold analysis"}
            </div>
            <div className="panel-sub">
              Every 6 hours each server's own history (up to the 7 days
              retained) is re-analysed — mean, σ, percentiles — to derive its
              upper and lower CPU/memory bounds (max(p95, μ+3σ) /
              min(p05, μ−3σ)), and the result is applied to its live alerts
              automatically. A server needs ≥24 h of history before it is
              analysed at all; until then it is listed as still collecting.
              You can also run it now, or apply manually.
            </div>
          </div>
        </div>
        <div style={{display:"flex", gap:8, alignItems:"center"}}>
          <select value={windowH} style={{width:130}}
                  onChange={function(e){ setWindowH(e.target.value); }}>
            <option value={24}>last 24 h</option>
            <option value={48}>last 2 days</option>
            <option value={72}>last 3 days</option>
            <option value={168}>all retained (7 d)</option>
          </select>
          <button className="secondary small" disabled={running} onClick={analyze}>
            <i className="uil uil-processor" /> {running ? "Analyzing…" : "Analyze now"}
          </button>
          {rows && rows.length ? (
            <button className="primary small" disabled={applying === "*/*"}
                    onClick={function(){ apply(only || null, null); }}>
              {only ? "Apply both sensors" : "Apply all"}
            </button>
          ) : null}
        </div>
      </div>

      {msg ? <div className="alert ok" style={{margin:"0 16px 10px"}}>{msg}</div> : null}
      {err ? <div className="alert error" style={{margin:"0 16px 10px"}}>{err}</div> : null}

      {rows === null ? (
        <div className="muted small" style={{padding:"0 16px 14px"}}>Loading…</div>
      ) : !rows.length ? (
        <div className="muted small" style={{padding:"0 16px 14px"}}>
          {only
            ? "No analysis stored for " + only + " yet — it needs ≥24 h of " +
              "history, or press Analyze now if it already has that."
            : "No stored analysis yet — press Analyze now. Servers need ≥24 h " +
              "of streamed history before thresholds can be derived."}
        </div>
      ) : (
        <table className="lacp-history" style={{marginBottom:8}}>
          <thead>
            <tr>{only ? null : <th>Server</th>}<th>Sensor</th><th>Samples</th>
                <th>Mean ± σ</th><th>p95 / p99</th>
                <th>Recommended</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {rows.map(function(r){
              const key = r.server + "/" + r.sensor;
              return (
                <React.Fragment key={key}>
                  <tr className="lacp-history-row"
                      onClick={function(){ setOpenRow(openRow === key ? "" : key); }}>
                    {only ? null : <td><strong>{r.server}</strong></td>}
                    <td>{sensorLabel(r.sensor)}</td>
                    <td>{r.sample_count}</td>
                    <td>{r.mean}% ± {r.std}</td>
                    <td>{r.p95}% / {r.p99}%</td>
                    <td>
                      <span className="pill err">↑ {r.rec_upper}%</span>{" "}
                      <span className="pill">↓ {r.rec_lower}%</span>{" "}
                      <span className="muted small">≥{r.rec_dwell_sec}s</span>
                    </td>
                    <td>{r.applied_at
                      ? <span className="pill ok">applied</span>
                      : <span className="pill warn">not applied</span>}</td>
                    <td>
                      <button className="secondary small"
                              disabled={applying === key}
                              onClick={function(ev){ ev.stopPropagation();
                                                     apply(r.server, r.sensor); }}>
                        {applying === key ? "…" : "Apply"}
                      </button>
                    </td>
                  </tr>
                  {openRow === key ? (
                    <tr><td colSpan={only ? 7 : 8}>
                      <div className="muted small" style={{lineHeight:1.7}}>
                        Window: last {r.window_hours}h ({r.coverage_hours}h of
                        data covered) · {r.sample_count} samples
                        · min {r.min}% · p05 {r.p05}% · median {r.p50}% ·
                        p95 {r.p95}% · p99 {r.p99}% · max {r.max}%<br/>
                        Method: {r.method} → upper {r.rec_upper}%, lower{" "}
                        {r.rec_lower}%, dwell {r.rec_dwell_sec}s (3× median
                        sample interval).
                        Computed {r.computed_at
                          ? new Date(r.computed_at).toLocaleString() : ""}.
                        {r.applied_at
                          ? " Applied to live alerts " +
                            new Date(r.applied_at).toLocaleString() + "."
                          : " Not yet applied to live alerts."}
                      </div>
                    </td></tr>
                  ) : null}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ── Server Audits — persistent alert trail for the server fleet ─────
// Active threshold breaches with acknowledge, plus recent cleared history.
// Backed by server_alert_events, which the scheduler raises/clears every 10s.
function ServerAuditsPanel(props) {
  const only = props && props.server ? props.server : "";
  const [data, setData]       = useState(null);
  const [showHist, setShowHist] = useState(false);
  const [err, setErr]         = useState("");
  const [acking, setAcking]   = useState(0);
  const [evidenceFor, setEvidenceFor] = useState(0);
  const [evidence, setEvidence]       = useState(null);

  // The metric snapshot taken when the alert fired — every sensor of that
  // server at that instant, kept even after the raw 7-day history is pruned.
  function showEvidence(id){
    if (evidenceFor === id) { setEvidenceFor(0); setEvidence(null); return; }
    setEvidenceFor(id); setEvidence(null);
    api("/api/servers/alerts/" + id + "/metrics")
      .then(setEvidence).catch(function(e){ setErr(e.message); });
  }

  function evidenceBlock(id){
    if (evidenceFor !== id) return null;
    if (!evidence) return <div className="muted small">loading evidence…</div>;
    return (
      <div className="alert-evidence">
        <div className="muted small" style={{marginBottom:4}}>
          All sensors at the moment this alert was raised
          {evidence.captured_at
            ? " (" + new Date(evidence.captured_at).toLocaleString() + ")" : ""}:
        </div>
        {(evidence.metrics || []).map(function(m, i){
          return (
            <div key={i} className={"lacp-check " + (m.is_trigger ? "fail" : "pass")}
                 style={{padding:"2px 2px"}}>
              <span className="lacp-check-name" style={{minWidth:220}}>
                {m.label}
              </span>
              <strong>{m.value}{m.unit}</strong>
              {m.is_trigger ? <span className="pill err" style={{marginLeft:6}}>
                triggered the alert</span> : null}
            </div>
          );
        })}
        {!(evidence.metrics || []).length
          ? <div className="muted small">no snapshot stored for this event</div>
          : null}
      </div>
    );
  }

  const load = useCallback(function(){
    api("/api/servers/alerts?limit=100")
      .then(function(d){
        // The endpoint returns the fleet; when this panel is mounted under a
        // single server we show only that server's alerts.
        if (only) {
          d = Object.assign({}, d, {
            alerts: (d.alerts || []).filter(function(a){ return a.server === only; }),
          });
        }
        setData(d); setErr("");
      })
      .catch(function(e){ setErr(e.message); });
  }, [only]);
  useEffect(function(){
    load();
    const t = setInterval(load, 8000);
    return function(){ clearInterval(t); };
  }, [load]);

  async function ack(id){
    setAcking(id);
    try {
      await api("/api/servers/alerts/" + id + "/ack", { method: "POST" });
      load();
    } catch(e){ setErr(e.message); }
    finally { setAcking(0); }
  }

  function fmtSensor(s){ return (s || "").replace(/_/g, " "); }
  function fmtWhen(iso){
    if (!iso) return "";
    try { return new Date(iso).toLocaleString(); } catch(e){ return iso; }
  }

  const alerts  = (data && data.alerts) || [];
  const active  = alerts.filter(function(a){ return a.state === "active"; });
  const cleared = alerts.filter(function(a){ return a.state !== "active"; });

  return (
    <div className="panel srv-audits">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-bell" />
          <div>
            <div className="panel-title">
              {only ? "Alerts — " + only : "Server audits"}
              {active.length
                ? <span className="pill err" style={{marginLeft:8}}>
                    {active.length} active alert{active.length === 1 ? "" : "s"}
                  </span>
                : <span className="pill ok" style={{marginLeft:8}}>all clear</span>}
            </div>
            <div className="panel-sub">
              Threshold breaches are raised here the moment they sustain past
              their dwell time, and cleared automatically when the value
              recovers. Acknowledging records who has seen an alert — it never
              silences detection.
            </div>
          </div>
        </div>
        <button className="secondary small"
                onClick={function(){ setShowHist(!showHist); }}>
          <i className="uil uil-history" /> {showHist ? "Hide" : "Show"} history
          {cleared.length ? " (" + cleared.length + ")" : ""}
        </button>
      </div>

      {err ? <div className="alert error">{err}</div> : null}

      {active.length === 0 && !showHist ? (
        <div className="muted small" style={{padding:"4px 16px 14px"}}>
          No active alerts. Set thresholds per sensor in each server's Alert
          Settings to arm monitoring.
        </div>
      ) : null}

      {active.map(function(a){
        return (
          <div key={a.id} className="srv-alert-row active-alert">
            <i className="uil uil-exclamation-octagon" />
            <div className="srv-alert-info">
              <div>
                <strong>{a.server}</strong> · {fmtSensor(a.sensor)}{" "}
                {a.kind === "upper" ? "above" : "below"}{" "}
                <strong>{a.threshold}{a.unit}</strong>
                {" — now "}{a.value}{a.unit}
                {a.worst_value !== a.value
                  ? " (worst " + a.worst_value + a.unit + ")" : ""}
              </div>
              <div className="muted small">
                raised {fmtWhen(a.raised_at)}
                {a.dwell_sec ? " · sustained ≥" + a.dwell_sec + "s" : ""}
                {a.acknowledged_by
                  ? " · ack'd by " + a.acknowledged_by : ""}
              </div>
            </div>
            <button className="secondary small"
                    onClick={function(){ showEvidence(a.id); }}>
              <i className="uil uil-file-search-alt" />{" "}
              {evidenceFor === a.id ? "Hide" : "Evidence"}
            </button>
            {!a.acknowledged_by ? (
              <button className="secondary small" disabled={acking === a.id}
                      onClick={function(){ ack(a.id); }}>
                {acking === a.id ? "…" : "Acknowledge"}
              </button>
            ) : <span className="pill">acknowledged</span>}
          </div>
        );
      })}
      {active.map(function(a){ return evidenceBlock(a.id); })}

      {showHist ? (
        cleared.length ? cleared.map(function(a){
          return (
            <div key={a.id} className="srv-alert-row cleared-alert">
              <i className="uil uil-check-circle" />
              <div className="srv-alert-info">
                <div>
                  <strong>{a.server}</strong> · {fmtSensor(a.sensor)}{" "}
                  {a.kind === "upper" ? "exceeded" : "fell below"}{" "}
                  {a.threshold}{a.unit} — peaked at {a.worst_value}{a.unit}
                </div>
                <div className="muted small">
                  {fmtWhen(a.raised_at)} → cleared {fmtWhen(a.cleared_at)}
                  {a.acknowledged_by ? " · ack'd by " + a.acknowledged_by : ""}
                </div>
              </div>
            </div>
          );
        }) : <div className="muted small" style={{padding:"4px 16px 14px"}}>
               No cleared alerts in recent history.
             </div>
      ) : null}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════
// SERVER DETAIL — everything about ONE server, tabbed like a switch.
// Performance monitoring · Server audits · Threshold analysis.
// The server list itself lives in the Dashboard sidebar (same as switches).
// ════════════════════════════════════════════════════════════════════

// Small rectangular live box: CPU, memory and the utilization category.
// Shown per row in the server column and enlarged on the detail header.
function LiveUtilBox(props) {
  const d = props.live || {};
  const cat = d.category || "unknown";
  const label = { idle: "Idle", low: "Low", medium: "Medium",
                  over: "Over-utilized", unknown: "No data" }[cat] || cat;
  const num = function(v){ return v == null ? "—" : v + "%"; };
  return (
    <div className={cls("util-box", "u-" + cat, props.big && "big")}
         title={d.derived_upper
           ? "Category is relative to this server's own analysed ceiling of "
             + d.derived_upper + "%"
           : "Category uses default bands — no baseline analysed yet"}>
      <div className="util-nums">
        <span><b>{num(d.cpu)}</b> cpu</span>
        <span><b>{num(d.memory)}</b> mem</span>
      </div>
      <div className="util-cat">
        {label}
        {d.live ? <i className="uil uil-signal-alt-3 util-live"
                     title="streaming now" /> : null}
      </div>
    </div>
  );
}

function ServerDetail(props) {
  const srv   = props.server;
  const live  = props.live || {};
  const [tab, setTab] = useState("performance");

  useEffect(function(){ setTab("performance"); }, [srv && srv.name]);

  if (!srv) {
    return (
      <div className="muted" style={{padding:"20px"}}>
        Select a server from the list to see its performance, alerts and
        threshold analysis.
      </div>
    );
  }

  const locked = live.locked || _srvIsAuthError(srv.last_poll_error);

  return (
    <div>
      <div className="panel" style={{marginBottom:12}}>
        <div className="panel-head">
          <div className="panel-id">
            <i className="uil uil-server" />
            <div>
              <div className="panel-title">
                {srv.name}
                {locked ? (
                  <span className="pill err" style={{marginLeft:8}}>
                    <i className="uil uil-lock" /> credentials rejected
                  </span>
                ) : null}
              </div>
              <div className="panel-sub">
                iLO {srv.ilo_host}
                {srv.description ? " · " + srv.description : ""}
                {srv.location ? " · " + srv.location : ""}
              </div>
            </div>
          </div>
          <div style={{display:"flex", gap:8, alignItems:"center"}}>
            <LiveUtilBox live={live} big />
            {locked ? (
              <button className="primary small"
                      onClick={function(){ props.onUnlock(srv); }}>
                <i className="uil uil-key-skeleton" /> Unlock
              </button>
            ) : null}
            <button className="secondary small"
                    onClick={function(){ props.onEdit(srv); }}>
              <i className="uil uil-edit" /> Edit
            </button>
          </div>
        </div>

        {locked ? (
          <div className="alert error" style={{margin:"0 16px 12px"}}>
            <i className="uil uil-lock" /> This server rejected the stored
            credentials, so no real data can be collected:
            <em> {srv.last_poll_error}</em>. Press <strong>Unlock</strong> to
            try a different username/password — nothing is saved unless it
            actually authenticates.
          </div>
        ) : null}

        <div className="modal-tabs" style={{padding:"0 16px"}}>
          {[["performance", "uil-chart-line", "Performance monitoring"],
            ["audits",      "uil-bell",       "Server audits"],
            ["thresholds",  "uil-chart-bar",  "Threshold analysis"]
          ].map(function(t){
            return (
              <button key={t[0]}
                      className={cls("modal-tab", tab === t[0] && "active")}
                      onClick={function(){ setTab(t[0]); }}>
                <i className={"uil " + t[1]} /> {t[2]}
              </button>
            );
          })}
        </div>
      </div>

      {tab === "performance" ? (
        <ServerMonitorPanel server={srv}
                            alert={props.alert}
                            onEdit={function(){ props.onEdit(srv); }}
                            onDeleted={props.onDeleted} />
      ) : null}
      {tab === "audits"     ? <ServerAuditsPanel server={srv.name} /> : null}
      {tab === "thresholds" ? <ThresholdAnalysisPanel server={srv.name} /> : null}
    </div>
  );
}

// Mirrors the backend's _is_auth_failure so the UI can offer Unlock for
// credential problems only — a timeout is not fixed by a new password.
function _srvIsAuthError(err) {
  const low = (err || "").toLowerCase();
  return ["401", "unauthorized", "authentication", "auth failed",
          "permission denied", "invalid credential", "bad password",
          "login incorrect", "access denied", "forbidden", "403"]
         .some(function(s){ return low.indexOf(s) !== -1; });
}

// Unlock dialog — same idea as the switch unlock: prove the credentials
// before they are stored.
function UnlockServerDialog(props) {
  const srv = props.server;
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState("");

  async function submit(){
    setBusy(true); setErr("");
    try {
      const r = await api("/api/servers/" + encodeURIComponent(srv.name) + "/unlock",
        { method: "POST", body: JSON.stringify({ username: u, password: p }) });
      props.onUnlocked(r);
    } catch(e){ setErr(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="modal" style={{maxWidth:460}}
           onClick={function(e){ e.stopPropagation(); }}>
        <h3><i className="uil uil-key-skeleton" /> Unlock {srv.name}</h3>
        <p className="muted small">
          iLO {srv.ilo_host}. The credentials are tested against the server
          (Redfish first, then SSH) and only saved if something answers — a
          wrong password can't overwrite a working one.
        </p>
        {srv.last_poll_error ? (
          <div className="muted small" style={{marginBottom:8}}>
            Last error: <em>{srv.last_poll_error}</em>
          </div>
        ) : null}
        <label style={{display:"block", marginBottom:8}}>Username
          <input type="text" value={u} autoFocus
                 onChange={function(e){ setU(e.target.value); }} />
        </label>
        <label style={{display:"block", marginBottom:10}}>Password
          <input type="password" value={p}
                 onChange={function(e){ setP(e.target.value); }}
                 onKeyDown={function(e){ if (e.key === "Enter" && u && p) submit(); }} />
        </label>
        {err ? <div className="alert error">{err}</div> : null}
        <div style={{display:"flex", gap:8, justifyContent:"flex-end"}}>
          <button className="secondary" onClick={props.onClose}>Cancel</button>
          <button className="primary" disabled={!u || !p || busy}
                  onClick={submit}>
            {busy ? "Testing…" : "Test & save"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ServersView is now just the DETAIL pane — the server list lives in the
// Dashboard sidebar exactly like the switch list, so servers and switches
// behave identically. Dashboard owns the selection and passes it down.
function ServersView(props) {
  const servers = props.servers || [];
  const active  = props.active;
  const alerts  = props.alerts || {};
  const liveAll = props.liveAll || {};
  const activeServer = servers.find(function(s){ return s.name === active; });

  if (!servers.length) {
    return (
      <div className="muted" style={{padding:"20px"}}>
        No servers yet. Use <strong>Add</strong> in the server list to import
        HPE servers from the iLO inventory — each is polled on its own
        interval and keeps a week of history.
      </div>
    );
  }

  return (
    <div style={{padding:14}}>
      <ServerDetail server={activeServer}
                    live={liveAll[active] || {}}
                    alert={alerts[active]}
                    onEdit={props.onEdit}
                    onUnlock={props.onUnlock}
                    onDeleted={props.reload} />
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// AgentView — tool-calling AI agent over the whole portal.
// Shows the answer AND the trace of tools it actually called, so the
// operator can verify the agent looked at real data.
// ────────────────────────────────────────────────────────────────────
function AgentView(props) {
  const [msgs, setMsgs]       = useState([]);
  const [input, setInput]     = useState("");
  const [busy, setBusy]       = useState(false);
  const [tools, setTools]     = useState([]);
  const [findings, setFind]   = useState([]);
  const [showTrace, setTrace] = useState({});

  useEffect(function(){
    api("/api/agent/tools").then(setTools).catch(function(){});
  }, []);

  const loadFindings = useCallback(function(){
    api("/api/agent/findings")
      .then(function(d){ setFind(d.findings || []); })
      .catch(function(){});
  }, []);
  useEffect(function(){
    loadFindings();
    const t = setInterval(loadFindings, 30000);
    return function(){ clearInterval(t); };
  }, [loadFindings]);

  async function ask(q) {
    const question = (q != null ? q : input).trim();
    if (!question || busy) return;
    setInput("");
    setMsgs(function(m){ return m.concat([{ role: "user", text: question }]); });
    setBusy(true);
    try {
      const r = await api("/api/agent/query", {
        method: "POST",
        body: JSON.stringify({ question: question, switch: props.activeSwitch || null }),
      });
      setMsgs(function(m){
        return m.concat([{ role: "agent", text: r.answer, trace: r.trace || [],
                           tools: r.tools_used || [], steps: r.steps,
                           model: r.model }]);
      });
    } catch (e) {
      setMsgs(function(m){ return m.concat([{ role: "error", text: e.message }]); });
    } finally { setBusy(false); }
  }

  const examples = [
    "Are there any IP conflicts right now?",
    "What changed in the config recently?",
    "Which ports have errors?",
    "How is CPU on my servers?",
  ];

  return (
    <div className="agent-wrap">
      <div className="panel">
        <div className="panel-head">
          <div className="panel-id">
            <i className="uil uil-robot" />
            <div>
              <div className="panel-title">AI Agent</div>
              <div className="panel-sub">
                Calls live tools against your fleet — {tools.length} available
              </div>
            </div>
          </div>
        </div>

        {findings.length > 0 ? (
          <div className="agent-findings">
            <div className="agent-findings-head">
              <i className="uil uil-bell" /> Noticed without being asked
            </div>
            {findings.slice(0, 6).map(function(f, i){
              return (
                <div key={i} className={"agent-finding sev-" + f.severity}>
                  <strong>{f.title}</strong>
                  <span className="muted small"> — {f.detail}</span>
                </div>
              );
            })}
          </div>
        ) : null}

        <div className="agent-chat">
          {msgs.length === 0 ? (
            <div className="agent-empty">
              <p className="muted">
                Ask about switches, drift, IP conflicts, port errors, or server
                metrics. The agent will look up real data before answering.
              </p>
              <div className="agent-examples">
                {examples.map(function(x){
                  return (
                    <button key={x} className="agent-example"
                            onClick={function(){ ask(x); }}>{x}</button>
                  );
                })}
              </div>
            </div>
          ) : null}

          {msgs.map(function(m, i){
            if (m.role === "user") {
              return <div key={i} className="agent-msg user">{m.text}</div>;
            }
            if (m.role === "error") {
              return <div key={i} className="alert error">{m.text}</div>;
            }
            return (
              <div key={i} className="agent-msg agent">
                <div className="agent-answer">{m.text}</div>
                {m.tools && m.tools.length ? (
                  <div className="agent-meta">
                    <button className="agent-trace-toggle"
                            onClick={function(){
                              setTrace(function(p){
                                const n = Object.assign({}, p); n[i] = !n[i]; return n;
                              });
                            }}>
                      <i className="uil uil-wrench" /> {m.tools.length} tool call(s)
                      {" "}· {m.steps} step(s) {showTrace[i] ? "▲" : "▼"}
                    </button>
                    {showTrace[i] ? (
                      <div className="agent-trace">
                        {m.trace.map(function(t, j){
                          return (
                            <div key={j} className="agent-trace-row">
                              <code>{t.tool}({JSON.stringify(t.args)})</code>
                              <div className="agent-trace-res">{t.result_preview}</div>
                            </div>
                          );
                        })}
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            );
          })}
          {busy ? (
            <div className="agent-msg agent">
              <span className="muted">Thinking and calling tools…</span>
            </div>
          ) : null}
        </div>

        <div className="agent-input">
          <input value={input} placeholder="Ask the agent about your fleet…"
                 disabled={busy}
                 onChange={function(e){ setInput(e.target.value); }}
                 onKeyDown={function(e){ if (e.key === "Enter") ask(); }} />
          <button className="primary" disabled={busy || !input.trim()}
                  onClick={function(){ ask(); }}>
            <i className="uil uil-message" /> Ask
          </button>
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// ConfigView — Phase 1: templates, preview/validation, compliance, audit.
// Nothing here applies configuration; preview is explicitly read-only.
// ────────────────────────────────────────────────────────────────────
function ConfigView(props) {
  const switches = props.switches || [];
  const [tab, setTab] = useState("templates");

  return (
    <div className="cfg-wrap">
      <div className="modal-tabs cfg-tabs">
        {[["templates","Templates","uil-file-alt"],
          ["lacp","LACP","uil-link"],
          ["changes","Changes","uil-check-circle"],
          ["compliance","Compliance","uil-shield-check"],
          ["audit","Audit log","uil-history"]].map(function(t){
          return (
            <button key={t[0]} className={cls("modal-tab", tab === t[0] && "active")}
                    onClick={function(){ setTab(t[0]); }}>
              <i className={"uil " + t[2]} /> {t[1]}
            </button>
          );
        })}
      </div>
      {tab === "templates"  ? <TemplatesPanel switches={switches} /> : null}
      {tab === "lacp"       ? <LacpPanel switches={switches} /> : null}
      {tab === "changes"    ? <ChangesPanel /> : null}
      {tab === "compliance" ? <CompliancePanel switches={switches} /> : null}
      {tab === "audit"      ? <AuditPanel /> : null}
    </div>
  );
}

// ── LACP quick-configuration ─────────────────────────────────────────
// "Engineer selects ports and clicks Configure LACP." A guided front end
// over the LACP Port-Channel templates: pick a switch, tick member ports
// (or select a range), preview the exact CLI, then dry-run/apply through
// the same guarded pipeline (checkpoint → apply → confirm window) as
// every other change. Nothing here has its own write path.
function LacpPanel(props) {
  const switches = props.switches || [];
  const [swName, setSwName]   = useState("");
  const [ports, setPorts]     = useState([]);
  const [portsAt, setPortsAt] = useState(null);
  const [loadingPorts, setLoadingPorts] = useState(false);
  const [selected, setSelected] = useState({});   // interface -> bool
  const [filter, setFilter]   = useState("");
  const [lagId, setLagId]     = useState("");
  const [mode, setMode]       = useState("active");
  const [desc, setDesc]       = useState("");
  const [tpls, setTpls]       = useState([]);
  const [gate, setGate]       = useState(null);
  const [busy, setBusy]       = useState(false);
  const [err, setErr]         = useState("");
  const [preview, setPreview] = useState(null);
  const [applyRes, setApplyRes] = useState(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [reason, setReason]   = useState("");
  const [applyTok, setTok]    = useState("");

  useEffect(function(){
    api("/api/templates").then(setTpls).catch(function(e){ setErr(e.message); });
    api("/api/config/status").then(setGate).catch(function(){});
  }, []);

  const sw = switches.find(function(s){ return s.name === swName; }) || null;
  const isComware = !!sw && sw.device_type === "hp_comware";
  const supported = !!sw && (sw.device_type === "aruba_aoscx" || isComware);
  const tplName = isComware ? "LACP Port-Channel (HP Comware)"
                            : "LACP Port-Channel (Aruba AOS-CX)";
  const tpl = supported
    ? tpls.find(function(t){ return t.name === tplName; }) : null;

  async function loadPorts(name){
    setSwName(name); setPorts([]); setPortsAt(null); setSelected({});
    setPreview(null); setApplyRes(null); setErr("");
    if (!name) return;
    setLoadingPorts(true);
    try {
      const r = await api("/api/port-stats/latest?switch_name=" +
                          encodeURIComponent(name), {}, name);
      setPorts(r.ports || []);
      setPortsAt(r.captured_at);
      if (!(r.ports || []).length) {
        setErr("No port capture exists for this switch yet — run a port-stats " +
               "capture first, or type the interfaces into the Templates tab.");
      }
    } catch(e){ setErr(e.message); }
    finally { setLoadingPorts(false); }
  }

  const chosen = ports.map(function(p){ return p.interface; })
                      .filter(function(i){ return !!selected[i]; });
  const shown = ports.filter(function(p){
    return !filter ||
      p.interface.toLowerCase().indexOf(filter.toLowerCase()) !== -1;
  });
  const upSelected = chosen.filter(function(i){
    const p = ports.find(function(x){ return x.interface === i; });
    return p && /up/i.test(p.link_state || "");
  });

  function buildVars(){
    const v = { lag_id: lagId, ports: chosen.join(", "), description: desc };
    if (!isComware) v.lacp_mode = mode;
    return v;
  }
  const ready = !!tpl && chosen.length >= 1 && !!lagId && !!desc;

  async function doPreview(){
    setErr(""); setBusy(true); setPreview(null); setApplyRes(null);
    try {
      const r = await api("/api/templates/preview", {
        method: "POST",
        body: JSON.stringify({ template_id: tpl.id, variables: buildVars(),
                               switches: [swName] }),
      });
      setPreview(r);
    } catch(e){ setErr(e.message); }
    finally { setBusy(false); }
  }

  async function doApply(dryRun){
    setErr(""); setBusy(true); setApplyRes(null);
    try {
      const r = await api("/api/config/apply", {
        method: "POST",
        headers: applyTok ? { "X-Apply-Token": applyTok } : {},
        body: JSON.stringify({
          template_id: tpl.id, variables: buildVars(), switches: [swName],
          reason: reason, dry_run: dryRun,
        }),
      });
      setApplyRes(r);
      setConfirmOpen(false);
    } catch(e){ setErr(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="panel" style={{margin:12}}>
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-link" />
          <div>
            <div className="panel-title">Configure LACP</div>
            <div className="panel-sub">
              Select member ports and bond them into a port-channel. The exact
              CLI is generated, previewed and applied with an automatic
              rollback checkpoint — no manual per-switch typing.
            </div>
          </div>
        </div>
      </div>

      <div className="ilo-section">
        <div className="ilo-h2">1 · Switch</div>
        <select value={swName} onChange={function(e){ loadPorts(e.target.value); }}>
          <option value="">— choose a switch —</option>
          {switches.map(function(s){
            return <option key={s.name} value={s.name}>
              {s.name} ({s.device_type})
            </option>;
          })}
        </select>
        {sw && !supported ? (
          <div className="alert warn" style={{marginTop:8}}>
            No LACP template for device type <code>{sw.device_type}</code> yet —
            supported here: aruba_aoscx, hp_comware.
          </div>
        ) : null}
      </div>

      {sw && supported ? (
        <div className="ilo-section">
          <div className="ilo-h2">
            2 · Member ports
            {chosen.length ? <span className="pill ok">{chosen.length} selected</span> : null}
          </div>
          {loadingPorts ? <div className="muted small">Loading ports…</div> : null}
          {ports.length ? (
            <div>
              <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap",marginBottom:8}}>
                <input value={filter} style={{maxWidth:260}}
                       placeholder={isComware ? 'filter range, e.g. "GE1/0/"' : 'filter range, e.g. "1/1/1"'}
                       onChange={function(e){ setFilter(e.target.value); }} />
                <button className="secondary" disabled={!shown.length}
                        onClick={function(){
                          setSelected(function(p){
                            const n = Object.assign({}, p);
                            shown.forEach(function(x){ n[x.interface] = true; });
                            return n;
                          });
                        }}>
                  Select shown ({shown.length})
                </button>
                <button className="secondary" disabled={!chosen.length}
                        onClick={function(){ setSelected({}); }}>
                  Clear
                </button>
                {portsAt ? <span className="muted small">port list captured {portsAt}</span> : null}
              </div>
              <div className="cfg-targets" style={{maxHeight:260,overflowY:"auto"}}>
                {shown.map(function(p){
                  const on = !!selected[p.interface];
                  const up = /up/i.test(p.link_state || "");
                  return (
                    <label key={p.interface} className={cls("chk", on && "on")}>
                      <input type="checkbox" checked={on}
                             onChange={function(){
                               setSelected(function(prev){
                                 const n = Object.assign({}, prev);
                                 n[p.interface] = !n[p.interface];
                                 return n;
                               });
                             }} />
                      <span>
                        {p.interface}{" "}
                        <span className={"pill " + (up ? "ok" : "")}>{p.link_state || "?"}</span>
                        {p.port_description
                          ? <span className="muted small"> {p.port_description}</span> : null}
                      </span>
                    </label>
                  );
                })}
              </div>
              {upSelected.length ? (
                <div className="alert warn" style={{marginTop:8}}>
                  {upSelected.length} selected port(s) are currently <strong>UP</strong>{" "}
                  ({upSelected.join(", ")}). Moving a live port into a LAG bounces
                  its traffic until LACP converges — check nothing critical
                  (especially not this portal's own path) rides on them.
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}

      {sw && supported ? (
        <div className="ilo-section">
          <div className="ilo-h2">3 · Bond settings</div>
          <div style={{display:"flex",gap:14,flexWrap:"wrap"}}>
            <label><div className="label-text">{isComware ? "Bridge-Aggregation #" : "LAG #"} <span style={{color:"var(--err)"}}>*</span></div>
              <input value={lagId} placeholder="e.g. 10" style={{maxWidth:120}}
                     onChange={function(e){ setLagId(e.target.value); }} />
            </label>
            {!isComware ? (
              <label><div className="label-text">LACP mode</div>
                <select value={mode} onChange={function(e){ setMode(e.target.value); }}>
                  <option value="active">active</option>
                  <option value="passive">passive</option>
                </select>
              </label>
            ) : (
              <label><div className="label-text">LACP mode</div>
                <input value="dynamic (LACP)" disabled style={{maxWidth:160}} />
              </label>
            )}
            <label style={{flex:1,minWidth:220}}>
              <div className="label-text">Description <span style={{color:"var(--err)"}}>*</span></div>
              <input value={desc} placeholder="e.g. bond to server rack B"
                     onChange={function(e){ setDesc(e.target.value); }} />
            </label>
          </div>
          {!isComware ? (
            <div className="muted small" style={{marginTop:6}}>
              At least one end of the bond must be <code>active</code> for LACP
              to negotiate. VLAN/trunk settings on the new LAG are left at
              defaults — apply an access/trunk template to it afterwards.
            </div>
          ) : (
            <div className="muted small" style={{marginTop:6}}>
              Comware joins members to a <code>dynamic</code> Bridge-Aggregation.
              Member ports carrying conflicting port-level config are rejected
              by the device — the per-command error handling will catch that
              and roll back.
            </div>
          )}
        </div>
      ) : null}

      {err ? <div className="alert error">{err}</div> : null}

      {sw && supported ? (
        <div style={{display:"flex",gap:10,alignItems:"center",marginTop:8,flexWrap:"wrap"}}>
          <button className="primary" disabled={busy || !ready} onClick={doPreview}>
            <i className="uil uil-eye" /> {busy ? "Rendering…" : "Preview CLI"}
          </button>
          <button className="secondary" disabled={busy || !ready}
                  onClick={function(){ doApply(true); }}>
            <i className="uil uil-flask" /> Dry run
          </button>
          {gate && gate.apply_enabled ? (
            <button className="danger" disabled={busy || !ready}
                    onClick={function(){ setConfirmOpen(true); }}>
              <i className="uil uil-upload" /> Configure LACP
            </button>
          ) : (
            <span className="pill" title="Set CONFIG_APPLY_ENABLED=1 on the backend">
              <i className="uil uil-lock" /> apply disabled
            </span>
          )}
          {!tpl && supported && tpls.length ? (
            <span className="muted small">
              Template “{tplName}” not found — restart the backend so the
              built-in templates re-seed.
            </span>
          ) : null}
        </div>
      ) : null}

      {preview ? <PreviewResults preview={preview} /> : null}
      {applyRes ? <ApplyResult res={applyRes} /> : null}

      {confirmOpen ? (
        <div className="modal-backdrop" onClick={function(){ setConfirmOpen(false); }}>
          <div className="modal" onClick={function(e){ e.stopPropagation(); }}>
            <div className="modal-head">
              <i className="uil uil-exclamation-octagon" style={{color:"var(--err)"}} />
              <div>
                <div className="modal-title">Configure LACP on {swName}</div>
                <div className="modal-sub">
                  LAG {lagId} · {chosen.length} member port(s)
                </div>
              </div>
            </div>
            <div className="modal-body">
              <div className="alert warn">
                A rollback checkpoint is taken on the device first. After
                applying you have{" "}
                <strong>{gate ? Math.round(gate.confirm_window_seconds/60) : 5} minutes</strong>{" "}
                to confirm in the <strong>Changes</strong> tab. If you don't —
                for example because the change cut you off — the switch reverts
                automatically.
              </div>
              <label><div className="label-text">Reason / change ticket</div>
                <input value={reason} placeholder="e.g. CHG-1077 new LACP bond"
                       onChange={function(e){ setReason(e.target.value); }} />
              </label>
              <label><div className="label-text">Apply token</div>
                <input type="password" value={applyTok} autoComplete="off"
                       placeholder="X-Apply-Token"
                       onChange={function(e){ setTok(e.target.value); }} />
              </label>
              <div className="modal-actions">
                <button className="secondary"
                        onClick={function(){ setConfirmOpen(false); }}>Cancel</button>
                <button className="danger" disabled={busy || !reason || !applyTok}
                        onClick={function(){ doApply(false); }}>
                  {busy ? "Applying…" : "Yes, configure LACP"}
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function TemplatesPanel(props) {
  const switches = props.switches;
  const [tpls, setTpls]     = useState([]);
  const [sel, setSel]       = useState(null);
  const [vars, setVars]     = useState({});
  const [targets, setTargets] = useState({});
  const [preview, setPreview] = useState(null);
  const [busy, setBusy]     = useState(false);
  const [err, setErr]       = useState("");
  const [gate, setGate]     = useState(null);      // /api/config/status
  const [reason, setReason] = useState("");
  const [applyTok, setTok]  = useState("");
  const [applyRes, setApplyRes] = useState(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  useEffect(function(){
    api("/api/templates").then(setTpls).catch(function(e){ setErr(e.message); });
    api("/api/config/status").then(setGate).catch(function(){});
  }, []);

  async function doApply(dryRun){
    setErr(""); setBusy(true); setApplyRes(null);
    try {
      const r = await api("/api/config/apply", {
        method:"POST",
        headers: applyTok ? { "X-Apply-Token": applyTok } : {},
        body: JSON.stringify({
          template_id: sel.id, variables: vars, switches: chosen,
          reason: reason, dry_run: dryRun,
        }),
      });
      setApplyRes(r);
      setConfirmOpen(false);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  function choose(t){
    setSel(t); setPreview(null); setErr("");
    const init = {};
    (t.variables || []).forEach(function(v){ init[v.name] = ""; });
    setVars(init);
    // Preselect only switches this template can target.
    const tg = {};
    switches.forEach(function(sw){
      if (!t.device_type || sw.device_type === t.device_type) tg[sw.name] = false;
    });
    setTargets(tg);
  }

  const eligible = sel
    ? switches.filter(function(sw){ return !sel.device_type || sw.device_type === sel.device_type; })
    : [];
  const chosen = Object.keys(targets).filter(function(k){ return targets[k]; });

  async function doPreview(){
    setErr(""); setBusy(true); setPreview(null);
    try {
      const r = await api("/api/templates/preview", {
        method:"POST",
        body: JSON.stringify({ template_id: sel.id, variables: vars, switches: chosen }),
      });
      setPreview(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="cfg-grid">
      <div className="cfg-side">
        <div className="sidebar-title">Templates ({tpls.length})</div>
        {tpls.map(function(t){
          return (
            <button key={t.id} className={cls("sw-row", sel && sel.id === t.id && "active")}
                    onClick={function(){ choose(t); }}>
              <i className="uil uil-file-alt" />
              <div className="sw-row-info">
                <div className="sw-row-name">{t.name}</div>
                <div className="sw-row-meta">
                  {t.category}{t.device_type ? " · " + t.device_type : " · any vendor"}
                </div>
              </div>
              {t.builtin ? <span className="pill">built-in</span> : null}
            </button>
          );
        })}
      </div>

      <div className="cfg-main">
        {!sel ? (
          <div className="muted" style={{padding:20}}>
            Select a template to fill in its variables and preview the exact CLI
            that would run. Nothing is applied to any device in this release.
          </div>
        ) : (
          <div className="panel">
            <div className="panel-head">
              <div className="panel-id">
                <i className="uil uil-file-alt" />
                <div>
                  <div className="panel-title">{sel.name}</div>
                  <div className="panel-sub">{sel.description}</div>
                </div>
              </div>
            </div>

            <div className="ilo-section">
              <div className="ilo-h2">Variables</div>
              {(sel.variables || []).map(function(v){
                return (
                  <label key={v.name} className="cfg-var">
                    <div className="label-text">
                      {v.name}
                      {v.required ? <span style={{color:"var(--err)"}}> *</span> : null}
                      <span className="muted small"> — {v.description}</span>
                    </div>
                    <input value={vars[v.name] || ""}
                           placeholder={v.type}
                           onChange={function(e){
                             const val=e.target.value;
                             setVars(function(p){ const n=Object.assign({},p); n[v.name]=val; return n; });
                           }} />
                  </label>
                );
              })}
            </div>

            <div className="ilo-section">
              <div className="ilo-h2">Target switches</div>
              {eligible.length === 0 ? (
                <div className="muted small">
                  No switches match this template's vendor ({sel.device_type}).
                </div>
              ) : null}
              <div className="cfg-targets">
                {eligible.map(function(sw){
                  return (
                    <label key={sw.name} className={cls("chk", targets[sw.name] && "on")}>
                      <input type="checkbox" checked={!!targets[sw.name]}
                             onChange={function(){
                               setTargets(function(p){
                                 const n=Object.assign({},p); n[sw.name]=!n[sw.name]; return n;
                               });
                             }} />
                      <span>{sw.name} <span className="muted small">{sw.host}</span></span>
                    </label>
                  );
                })}
              </div>
              <div className="muted small" style={{marginTop:6}}>
                Selecting several switches previews the change for each — this is
                how bulk operations will be reviewed before they can ever run.
              </div>
            </div>

            {err ? <div className="alert error">{err}</div> : null}

            <div style={{display:"flex",gap:10,alignItems:"center",marginTop:8,flexWrap:"wrap"}}>
              <button className="primary" disabled={busy} onClick={doPreview}>
                <i className="uil uil-eye" /> {busy ? "Rendering…" : "Preview"}
              </button>
              <button className="secondary" disabled={busy || !chosen.length}
                      onClick={function(){ doApply(true); }}>
                <i className="uil uil-flask" /> Dry run
              </button>
              {gate && gate.apply_enabled ? (
                <button className="danger" disabled={busy || !chosen.length}
                        onClick={function(){ setConfirmOpen(true); }}>
                  <i className="uil uil-upload" /> Apply to {chosen.length} switch(es)
                </button>
              ) : (
                <span className="pill" title="Set CONFIG_APPLY_ENABLED=1 on the backend">
                  <i className="uil uil-lock" /> apply disabled
                </span>
              )}
            </div>

            {gate && !gate.apply_enabled ? (
              <div className="muted small" style={{marginTop:6}}>
                Writing configuration is switched off on this backend. Preview
                and dry run show exactly what would be sent, including the
                rollback commands.
              </div>
            ) : null}

            {preview ? <PreviewResults preview={preview} /> : null}
            {applyRes ? <ApplyResult res={applyRes} /> : null}

            {confirmOpen ? (
              <div className="modal-backdrop" onClick={function(){ setConfirmOpen(false); }}>
                <div className="modal" onClick={function(e){ e.stopPropagation(); }}>
                  <div className="modal-head">
                    <i className="uil uil-exclamation-octagon" style={{color:"var(--err)"}} />
                    <div>
                      <div className="modal-title">Apply to production</div>
                      <div className="modal-sub">
                        {chosen.length} switch(es) · {sel.name}
                      </div>
                    </div>
                  </div>
                  <div className="modal-body">
                    <div className="alert warn">
                      A rollback checkpoint is taken on each device first. After
                      applying you have{" "}
                      <strong>{gate ? Math.round(gate.confirm_window_seconds/60) : 5} minutes</strong>{" "}
                      to confirm. If you do not confirm — for example because the
                      change cut you off — the switch reverts automatically.
                    </div>
                    <label><div className="label-text">Reason / change ticket</div>
                      <input value={reason} placeholder="e.g. CHG-1042 new server bond"
                             onChange={function(e){ setReason(e.target.value); }} />
                    </label>
                    <label><div className="label-text">Apply token</div>
                      <input type="password" value={applyTok} autoComplete="off"
                             placeholder="X-Apply-Token"
                             onChange={function(e){ setTok(e.target.value); }} />
                    </label>
                    <div className="modal-actions">
                      <button className="secondary"
                              onClick={function(){ setConfirmOpen(false); }}>Cancel</button>
                      <button className="danger" disabled={busy || !reason || !applyTok}
                              onClick={function(){ doApply(false); }}>
                        {busy ? "Applying…" : "Yes, apply now"}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}

function PreviewResults(props) {
  const p = props.preview;
  return (
    <div className="ilo-section">
      <div className="ilo-h2">
        Preview {p.all_ok ? <span className="pill ok">valid</span>
                          : <span className="pill err">has problems</span>}
      </div>
      {p.results.map(function(r, i){
        return (
          <div key={i} className="cfg-result">
            <div className="cfg-result-head">
              <strong>{r.switch || "(no target selected)"}</strong>
              {r.ok ? <span className="pill ok">would apply cleanly</span>
                    : <span className="pill err">blocked</span>}
            </div>

            {(r.errors || []).map(function(e,j){
              return <div key={j} className="alert error">{e}</div>;
            })}
            {(r.blockers || []).map(function(b,j){
              return <div key={j} className="alert error"><strong>Blocker:</strong> {b}</div>;
            })}
            {(r.warnings || []).map(function(w,j){
              return <div key={j} className="alert warn"><strong>Warning:</strong> {w}</div>;
            })}
            {r.note ? <div className="muted small">{r.note}</div> : null}

            {r.rendered ? (
              <pre className="cfg-cli">
                {(r.commands || []).map(function(line, k){
                  const already = (r.already_present || []).indexOf(line) !== -1;
                  return (
                    <div key={k} className={already ? "cli-noop" : "cli-new"}>
                      <span className="cli-mark">{already ? " " : "+"}</span>
                      {line}
                    </div>
                  );
                })}
              </pre>
            ) : null}

            {r.would_change ? (
              <div className="muted small">
                {r.would_change.length} line(s) would change ·{" "}
                {(r.already_present || []).length} already present
                {r.snapshot_at ? " · compared with snapshot " + r.snapshot_at : ""}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function ApplyResult(props) {
  const r = props.res;
  if (r.executed === false || r.status === "dry_run") {
    return (
      <div className="ilo-section">
        <div className="ilo-h2">Dry run <span className="pill ok">nothing was sent</span></div>
        <pre className="cfg-cli">
          {(r.would_send || []).map(function(l,i){
            return <div key={i} className="cli-new"><span className="cli-mark">+</span>{l}</div>;
          })}
        </pre>
        {r.rollback_plan ? (
          <div className="muted small">
            Rollback plan · checkpoint: <code>{(r.rollback_plan.checkpoint_cmd||[]).join("; ")}</code>
            {" "}· revert: <code>{(r.rollback_plan.rollback_cmd||[]).join("; ")}</code>
          </div>
        ) : null}
        {(r.warnings || []).map(function(w,i){
          return <div key={i} className="alert warn">Warning: {w}</div>;
        })}
      </div>
    );
  }
  return (
    <div className="ilo-section">
      <div className="ilo-h2">
        Applied — change #{r.id}{" "}
        <span className={"pill " + (r.status === "awaiting_confirmation" ? "warn" : "err")}>
          {r.status.replace(/_/g," ")}
        </span>
      </div>
      <div className="muted small">
        Review the switches below and confirm in the <strong>Changes</strong> tab
        before the window expires, or they revert automatically.
      </div>
      {(r.targets || []).map(function(t){
        return (
          <div key={t.switch} className="cfg-result">
            <div className="cfg-result-head">
              <strong>{t.switch}</strong>
              <span className={"pill " + (t.status === "pending_confirm" ? "warn"
                              : t.status === "confirmed" ? "ok" : "err")}>
                {t.status.replace(/_/g," ")}
              </span>
            </div>
            {t.error ? <div className="alert error">{t.error}</div> : null}
            {t.rollback_error ? (
              <div className="alert error">
                <strong>ROLLBACK FAILED:</strong> {t.rollback_error} — this device
                needs manual attention.
              </div>
            ) : null}
            {t.checkpoint ? <div className="muted small">checkpoint: <code>{t.checkpoint}</code></div> : null}
          </div>
        );
      })}
    </div>
  );
}

function Countdown(props) {
  const [left, setLeft] = useState(0);
  useEffect(function(){
    function tick(){
      const ms = new Date(props.deadline).getTime() - Date.now();
      setLeft(Math.max(0, Math.floor(ms/1000)));
    }
    tick();
    const t = setInterval(tick, 1000);
    return function(){ clearInterval(t); };
  }, [props.deadline]);
  if (left <= 0) return <span className="pill err">window expired — reverting</span>;
  const m = Math.floor(left/60), sec = left % 60;
  return (
    <span className={cls("pill", left < 60 ? "err" : "warn")}>
      auto-revert in {m}:{("0"+sec).slice(-2)}
    </span>
  );
}

function ChangesPanel() {
  const [rows, setRows] = useState([]);
  const [tok, setTok]   = useState("");
  const [err, setErr]   = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(function(){
    api("/api/config/changes?limit=50").then(setRows).catch(function(e){ setErr(e.message); });
  }, []);
  useEffect(function(){
    load();
    const t = setInterval(load, 5000);
    return function(){ clearInterval(t); };
  }, [load]);

  async function act(id, what){
    setErr(""); setBusy(true);
    try {
      await api("/api/config/changes/" + id + "/" + what, {
        method:"POST", headers: tok ? { "X-Apply-Token": tok } : {},
      });
      load();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  const pending = rows.filter(function(r){
    return (r.targets||[]).some(function(t){ return t.status === "pending_confirm"; });
  });

  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-check-circle" />
          <div>
            <div className="panel-title">Changes</div>
            <div className="panel-sub">
              {pending.length} awaiting confirmation · {rows.length} total
            </div>
          </div>
        </div>
      </div>
      {err ? <div className="alert error">{err}</div> : null}

      {pending.length ? (
        <label style={{maxWidth:320,marginBottom:12,display:"block"}}>
          <div className="label-text">Apply token (needed to confirm or roll back)</div>
          <input type="password" value={tok} autoComplete="off"
                 onChange={function(e){ setTok(e.target.value); }} />
        </label>
      ) : null}

      {rows.length === 0 ? <div className="muted">No changes recorded.</div> : null}

      {rows.map(function(r){
        const needsConfirm = (r.targets||[]).some(function(t){ return t.status==="pending_confirm"; });
        const dl = (r.targets||[]).map(function(t){ return t.confirm_deadline; }).filter(Boolean)[0];
        return (
          <div key={r.id} className={"cfg-report st-" + (r.status==="completed"?"pass":r.status==="failed"?"fail":"warn")}>
            <div className="cfg-report-head" style={{cursor:"default"}}>
              <strong>#{r.id} {r.template}</strong>
              <span className="muted small">{r.requested_by}{r.reason ? " · " + r.reason : ""}</span>
              <span style={{flex:1}} />
              {r.dry_run ? <span className="pill">dry run</span> : null}
              <span className="pill">{r.status.replace(/_/g," ")}</span>
              {needsConfirm && dl ? <Countdown deadline={dl} /> : null}
            </div>
            <div className="cfg-report-body">
              {(r.targets||[]).map(function(t){
                return (
                  <div key={t.switch} className="cfg-rule">
                    <span className={"pill " + (t.status==="confirmed"?"ok":
                                     t.status==="pending_confirm"?"warn":"err")}>
                      {t.status.replace(/_/g," ")}
                    </span>
                    <div>
                      <strong>{t.switch}</strong>
                      {t.checkpoint ? <div className="muted small">checkpoint {t.checkpoint}</div> : null}
                      {t.error ? <div className="muted small" style={{color:"var(--err)"}}>{t.error}</div> : null}
                      {t.rollback_error ? (
                        <div className="alert error">ROLLBACK FAILED: {t.rollback_error}</div>
                      ) : null}
                    </div>
                  </div>
                );
              })}
              {needsConfirm ? (
                <div style={{display:"flex",gap:8,marginTop:10}}>
                  <button className="primary" disabled={busy || !tok}
                          onClick={function(){ act(r.id,"confirm"); }}>
                    <i className="uil uil-check" /> Keep change
                  </button>
                  <button className="danger" disabled={busy || !tok}
                          onClick={function(){ act(r.id,"rollback"); }}>
                    <i className="uil uil-history" /> Roll back now
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function CompliancePanel(props) {
  const [report, setReport] = useState(null);
  const [rules, setRules]   = useState([]);
  const [busy, setBusy]     = useState(false);
  const [err, setErr]       = useState("");
  const [open, setOpen]     = useState({});

  const run = useCallback(function(){
    setBusy(true); setErr("");
    api("/api/compliance/check")
      .then(setReport).catch(function(e){ setErr(e.message); })
      .finally(function(){ setBusy(false); });
  }, []);

  useEffect(function(){
    run();
    api("/api/compliance/rules").then(setRules).catch(function(){});
  }, [run]);

  const sum = report ? report.summary : {};
  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-shield-check" />
          <div>
            <div className="panel-title">Compliance</div>
            <div className="panel-sub">
              {rules.length} rule(s) checked against each switch's latest snapshot
            </div>
          </div>
        </div>
        <div className="panel-id-right">
          <button className="secondary small" onClick={run} disabled={busy}>
            <i className="uil uil-sync" /> {busy ? "Checking…" : "Re-check"}
          </button>
        </div>
      </div>

      {err ? <div className="alert error">{err}</div> : null}

      {report ? (
        <div className="cfg-summary">
          {[["pass","ok"],["warn","warn"],["fail","err"],["no_data",""]].map(function(k){
            return (
              <div key={k[0]} className={"cfg-stat " + k[1]}>
                <div className="cfg-stat-n">{sum[k[0]] || 0}</div>
                <div className="cfg-stat-l">{k[0].replace("_"," ")}</div>
              </div>
            );
          })}
        </div>
      ) : null}

      {report ? report.reports.map(function(r){
        const isOpen = !!open[r.switch];
        return (
          <div key={r.switch} className={"cfg-report st-" + r.status}>
            <button className="cfg-report-head"
                    onClick={function(){
                      setOpen(function(p){ const n=Object.assign({},p); n[r.switch]=!n[r.switch]; return n; });
                    }}>
              <span className={"thresh-dot " + (r.status==="pass"?"good":r.status==="no_data"?"":"bad")} />
              <strong>{r.switch}</strong>
              <span className="muted small">{r.device_type}</span>
              <span style={{flex:1}} />
              {r.status === "no_data"
                ? <span className="pill">no snapshot</span>
                : <span className={"pill " + (r.status==="pass"?"ok":"err")}>
                    {r.status === "pass" ? "compliant" : r.failed + " failing"}
                  </span>}
              <i className={"uil uil-angle-" + (isOpen ? "up" : "down")} />
            </button>
            {isOpen ? (
              <div className="cfg-report-body">
                {r.note ? <div className="muted small">{r.note}</div> : null}
                {(r.results || []).map(function(x){
                  return (
                    <div key={x.rule_id} className={"cfg-rule r-" + x.status}>
                      <span className={"pill " + (x.status==="pass"?"ok":"err")}>{x.status}</span>
                      <div>
                        <strong>{x.name}</strong>{" "}
                        <span className="muted small">({x.severity})</span>
                        <div className="muted small">{x.description}</div>
                        <div className="muted small">{x.detail}</div>
                        {x.matches && x.matches.length ? (
                          <pre className="cfg-cli small">{x.matches.join("\n")}</pre>
                        ) : null}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : null}
          </div>
        );
      }) : null}
    </div>
  );
}

function AuditPanel() {
  const [rows, setRows] = useState([]);
  const [err, setErr]   = useState("");
  useEffect(function(){
    api("/api/audit?limit=200").then(setRows).catch(function(e){ setErr(e.message); });
  }, []);
  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-history" />
          <div>
            <div className="panel-title">Audit log</div>
            <div className="panel-sub">Who changed what, when — {rows.length} recent events</div>
          </div>
        </div>
      </div>
      {err ? <div className="alert error">{err}</div> : null}
      <table className="table">
        <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th></tr></thead>
        <tbody>
          {rows.map(function(e){
            return (
              <tr key={e.id}>
                <td className="muted small">{new Date(e.timestamp).toLocaleString()}</td>
                <td>{e.actor}</td>
                <td><code>{e.action}</code></td>
                <td>{e.target}</td>
                <td>{e.success
                  ? <span className="pill ok">ok</span>
                  : <span className="pill err">failed</span>}</td>
              </tr>
            );
          })}
          {rows.length === 0 ? <tr><td colSpan="5" className="muted">No events yet.</td></tr> : null}
        </tbody>
      </table>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Dashboard — main app after login
// ────────────────────────────────────────────────────────────────────
function AddSwitchInventoryDialog(props) {
  const onClose = props.onClose, onImported = props.onImported;
  const [inv, setInv]     = useState([]);
  const [sel, setSel]     = useState({});
  const [creds, setCreds] = useState({ username:"", password:"" });
  const [err, setErr]     = useState("");
  const [busy, setBusy]   = useState(false);
  const [result, setResult] = useState(null);

  useEffect(function(){
    api("/api/inventory/switches")
      .then(function(d){ setInv(d.switches || []); })
      .catch(function(e){ setErr(e.message); });
  }, []);

  function toggle(ip){
    setSel(function(p){ const n=Object.assign({},p); if(n[ip]) delete n[ip]; else n[ip]=true; return n; });
  }
  const chosen = Object.keys(sel);

  async function submit(e){
    if (e) e.preventDefault();
    setErr("");
    if (!chosen.length) { setErr("Select at least one switch."); return; }
    if (!(creds.username && creds.password)) { setErr("Enter the switch username and password."); return; }
    setBusy(true);
    try {
      const r = await api("/api/switches/import", {
        method:"POST",
        body: JSON.stringify({ ips: chosen, username: creds.username, password: creds.password }),
      });
      setResult(r);
      if (r.added_count > 0) onImported(r);
    } catch (e2) { setErr(e2.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={function(e){ e.stopPropagation(); }}>
        <div className="modal-head">
          <i className="uil uil-plus-circle" />
          <div>
            <div className="modal-title">Add switches</div>
            <div className="modal-sub">Pick from the known fleet — credentials are never stored</div>
          </div>
          <button className="icon-btn" onClick={onClose}><i className="uil uil-times" /></button>
        </div>
        <form className="modal-body" onSubmit={submit}>
          {result ? (
            <div className="alert ok">
              Added {result.added_count}.
              {result.skipped.length ? " Skipped " + result.skipped.length + " already present." : ""}
              {result.added.filter(function(a){ return !a.reachable; }).length
                ? " Some were added but are not reachable with those credentials." : ""}
            </div>
          ) : null}
          <div className="inv-list">
            {inv.map(function(r){
              return (
                <label key={r.ip} className={cls("inv-row", r.already_added && "disabled", sel[r.ip] && "sel")}>
                  <input type="checkbox" disabled={r.already_added}
                         checked={!!sel[r.ip]} onChange={function(){ toggle(r.ip); }} />
                  <div className="inv-main">
                    <div className="inv-ip">{r.name} — {r.ip}
                      {r.already_added ? <span className="pill" style={{marginLeft:8}}>added</span> : null}
                    </div>
                    <div className="inv-meta">
                      {[r.role, r.model, r.device_type].filter(Boolean).join(" · ")}
                    </div>
                  </div>
                </label>
              );
            })}
            {inv.length === 0 ? <div className="muted small">Catalog is empty.</div> : null}
          </div>
          <div className="inv-creds">
            <div className="row two">
              <label><div className="label-text">Switch username</div>
                <input value={creds.username} autoComplete="off"
                       onChange={function(e){ const v=e.target.value; setCreds(function(p){return Object.assign({},p,{username:v});}); }} />
              </label>
              <label><div className="label-text">Switch password</div>
                <input type="password" value={creds.password} autoComplete="off"
                       onChange={function(e){ const v=e.target.value; setCreds(function(p){return Object.assign({},p,{password:v});}); }} />
              </label>
            </div>
            <div className="muted small">
              These credentials are used to reach the selected switches. They
              are not kept in the catalog.
            </div>
          </div>
          {err ? <div className="alert error">{err}</div> : null}
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={onClose}>Close</button>
            <button type="submit" className="primary" disabled={busy || !chosen.length}>
              {busy ? "Adding…" : "Add " + (chosen.length || "") + " switch" + (chosen.length === 1 ? "" : "es")}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// HASH ROUTING — the URL tracks the current view (#/switches, #/servers,
// #/links, #/conflicts, #/lacp, #/config, #/agent). Deep links work, the
// browser Back/Forward buttons work, and a refresh lands on the same page.
// ────────────────────────────────────────────────────────────────────
const ROUTED_VIEWS = ["switches", "conflicts", "servers", "links",
                      "lacp", "config", "agent"];

function getViewFromHash() {
  const parts = window.location.hash.replace(/^#\/?/, "").split("/")
    .filter(Boolean);
  const v = (parts[0] || "").toLowerCase();
  return ROUTED_VIEWS.indexOf(v) >= 0 ? v : "switches";
}

function useHashedView(view, setView) {
  // keep the URL in step with the state
  useEffect(function() {
    const want = "#/" + view;
    if (window.location.hash !== want) {
      window.location.hash = want;
    }
  }, [view]);

  // browser back/forward (and hand-edited URLs) drive the state
  useEffect(function() {
    function onHashChange() {
      const v = getViewFromHash();
      setView(function(cur){ return cur === v ? cur : v; });
    }
    window.addEventListener("hashchange", onHashChange);
    return function(){ window.removeEventListener("hashchange", onHashChange); };
  }, [setView]);
}

function Dashboard(props) {
  const switches       = props.switches;
  const reloadSwitches = props.reloadSwitches;
  const onLogoutAll    = props.onLogoutAll;

  const [view, setView]       = useState(getViewFromHash());  // URL-backed
  useHashedView(view, setView);
  const [active, setActive]   = useState(null);
  const [unlockSw, setUnlock] = useState(null);
  const [showAdd, setShowAdd] = useState(false);

  // Switch list: search box, catalog import, and inline edit.
  const [swQ, setSwQ]            = useState("");
  const [showSwImport, setSwImp] = useState(false);
  const [editSw, setEditSw]      = useState(null);

  // ── Server list — mirrors the switch list, so both live in this sidebar.
  const [servers, setServers]     = useState([]);
  const [srvActive, setSrvActive] = useState(null);
  const [srvQ, setSrvQ]           = useState("");

  const [srvAlerts, setSrvAlerts] = useState({});   // name -> alert-status
  const [liveAll, setLiveAll]     = useState({});   // name -> live cpu/mem/cat
  const [showSrvAdd, setSrvAdd]   = useState(false);
  const [editSrv, setEditSrv]     = useState(null);
  const [unlockSrv, setUnlockSrv] = useState(null);
  const [srvErr, setSrvErr]       = useState("");

  const loadServers = useCallback(async function(){
    try {
      const rows = await api("/api/servers");
      setServers(rows);
      setSrvErr("");
      setSrvActive(function(cur){
        if (cur && rows.some(function(s){ return s.name === cur; })) return cur;
        return rows.length ? rows[0].name : null;
      });
    } catch(e){ setSrvErr(e.message); }
  }, []);

  useEffect(function(){
    loadServers();
    const t = setInterval(loadServers, 30000);
    return function(){ clearInterval(t); };
  }, [loadServers]);

  // Threshold state (colouring) and live utilization (the small boxes) are
  // two cheap fleet-wide calls, polled only while the servers view is open.
  useEffect(function(){
    if (view !== "servers") return;
    function tick(){
      api("/api/servers/alert-status").then(function(d){
        const m = {};
        (d.servers || []).forEach(function(x){ m[x.server] = x; });
        setSrvAlerts(m);
      }).catch(function(){});
      api("/api/servers/live-all").then(function(d){
        const m = {};
        (d.servers || []).forEach(function(x){ m[x.server] = x; });
        setLiveAll(m);
      }).catch(function(){});
    }
    tick();
    const t = setInterval(tick, 5000);
    return function(){ clearInterval(t); };
  }, [view]);

  const shownServers = useMemo(function(){
    const f = srvQ.trim().toLowerCase();
    let list = servers;
    if (f) {
      list = servers.filter(function(s){
        return ((s.name || "") + " " + (s.ilo_host || "") + " " +
                (s.location || "") + " " + (s.description || ""))
                 .toLowerCase().indexOf(f) !== -1;
      });
    }
    // breaching servers first — that's the point of the colouring
    return list.slice().sort(function(a, b){
      const ab = (srvAlerts[a.name] || {}).state === "breach" ? 0 : 1;
      const bb = (srvAlerts[b.name] || {}).state === "breach" ? 0 : 1;
      if (ab !== bb) return ab - bb;
      return (a.name || "").localeCompare(b.name || "");
    });
  }, [servers, srvQ, srvAlerts]);

  const srvBreachCount = Object.keys(srvAlerts).filter(function(n){
    return srvAlerts[n].state === "breach";
  }).length;

  const [, set_]              = useState(0);
  const forceUpdate           = function(){ set_(function(x){ return x + 1; }); };

  const tokens    = getTokens();
  const usernames = getUsernames();

  useEffect(function() {
    if (!switches.length) {
      if (active) setActive(null);
      return;
    }

    const exists = switches.some(function(s){ return s.name === active; });
    if (active && !exists) {
      setActive(null);
      return;
    }

    if (!active) {
      const firstUnlocked = switches.find(function(s){ return tokens[s.name]; });
      if (firstUnlocked) setActive(firstUnlocked.name);
    }
  }, [switches]);

  const activeSw = useMemo(function() {
    return switches.find(function(s){ return s.name === active; });
  }, [switches, active]);
  // Snapshot the fleet to Excel: one sheet per server, 7 days of history.
  // Built server-side and streamed back, so a fetch plus an object URL is all
  // that is needed — the session cookie authenticates the download.
  const [exporting, setExporting] = useState(false);
  async function exportServers(){
    setExporting(true);
    try {
      const r = await fetch(API + "/api/servers/export.xlsx?days=7&bucket_minutes=5",
                            { credentials: "same-origin" });
      if (!r.ok) {
        let msg = "Export failed (" + r.status + ")";
        try { const j = await r.json(); if (j.detail) msg = j.detail; } catch (e) {}
        throw new Error(msg);
      }
      const blob = await r.blob();
      const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "noc-servers-" + stamp + ".xlsx";
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      setTimeout(function(){ URL.revokeObjectURL(url); }, 5000);
    } catch (e) {
      alert(e.message);
    } finally { setExporting(false); }
  }

function lockSwitch(name) {
    removeTokenFor(name);
    forceUpdate();
  }


  const unlockedCount = switches.filter(function(s){ return tokens[s.name]; }).length;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <i className="uil uil-server-network" />
          <span>NOC Portal</span>
        </div>
        <div className="topbar-info">
          <span className="pill ok">{unlockedCount} unlocked</span>
          <span className="pill">{switches.length - unlockedCount} locked</span>
          <button className="secondary small" onClick={function(){ setShowAdd(true); }}>
            <i className="uil uil-plus" /> Add switch
          </button>
          <button className="danger small" onClick={onLogoutAll}>
            <i className="uil uil-signout" /> Logout
          </button>
        </div>
      </header>

      {/* Full-width horizontal nav — no sideways scrolling. */}
      <nav className="mainnav">
        <button className={cls("mainnav-tab", view === "switches" && "active")}
                onClick={function(){ setView("switches"); }}>
          <i className="uil uil-server" /> <span>Switches</span>
        </button>
        <button className={cls("mainnav-tab", view === "conflicts" && "active")}
                onClick={function(){ setView("conflicts"); }}>
          <i className="uil uil-exclamation-triangle" /> <span>IP Conflicts</span>
        </button>
        <button className={cls("mainnav-tab", view === "servers" && "active")}
                onClick={function(){ setView("servers"); }}>
          <i className="uil uil-database" /> <span>Servers</span>
        </button>
        <button className={cls("mainnav-tab", view === "links" && "active")}
                onClick={function(){ setView("links"); }}>
          <i className="uil uil-link" /> <span>Links</span>
        </button>
        <button className={cls("mainnav-tab", view === "lacp" && "active")}
                onClick={function(){ setView("lacp"); }}>
          <i className="uil uil-sitemap" /> <span>LACP</span>
        </button>
        <button className={cls("mainnav-tab", view === "config" && "active")}
                onClick={function(){ setView("config"); }}>
          <i className="uil uil-file-edit-alt" /> <span>Config</span>
        </button>
        <button className={cls("mainnav-tab", view === "agent" && "active")}
                onClick={function(){ setView("agent"); }}>
          <i className="uil uil-robot" /> <span>AI Agent</span>
        </button>
      </nav>

      <div className="layout">
        <aside className="sidebar">
          {view === "switches" ? (
            <React.Fragment>
              <div className="ilo-list-head">
                <span>Switches ({switches.length})</span>
                <button className="primary small" onClick={function(){ setSwImp(true); }}>
                  <i className="uil uil-plus" /> Add
                </button>
              </div>

              <div className="search-wrap">
                <i className="uil uil-search" />
                <input className="search-input" value={swQ} placeholder="Search switches…"
                       onChange={function(e){ setSwQ(e.target.value); }} />
                {swQ ? (
                  <button className="icon-btn" onClick={function(){ setSwQ(""); }}>
                    <i className="uil uil-times" />
                  </button>
                ) : null}
              </div>

              {switches.length === 0 ? (
                <div className="muted small">No switches yet. Add some from the catalog.</div>
              ) : null}
              {switches.filter(function(sw){
                const f = swQ.trim().toLowerCase();
                if (!f) return true;
                return ((sw.name||"") + " " + (sw.host||"") + " " +
                        (sw.device_type||"") + " " + (sw.location||""))
                        .toLowerCase().indexOf(f) !== -1;
              }).map(function(sw) {
                const isUnlocked = !!tokens[sw.name];
                return (
                  <button key={sw.name}
                          className={cls("sw-row", active === sw.name && "active")}
                          onClick={function(){ setActive(sw.name); }}>
                    <i className={"uil uil-" + (isUnlocked ? "lock-open-alt" : "lock")} />
                    <div className="sw-row-info">
                      <div className="sw-row-name">{sw.name}</div>
                      <div className="sw-row-meta">{sw.host} · {sw.device_type}</div>
                    </div>
                    <span className="row-actions">
                      <i className="uil uil-edit edit-ico" title="Edit switch"
                         onClick={function(e){ e.stopPropagation(); setEditSw(sw); }} />
                    </span>
                    <span className={"dot " + (isUnlocked ? "ok" : "warn")}
                          title={isUnlocked ? "unlocked" : "locked"} />
                  </button>
                );
              })}
            </React.Fragment>
          ) : view === "config" ? (
            <div className="muted small" style={{margin:"12px 8px"}}>
              Configuration templates, CLI preview, and compliance checks.
              This release is read-only: you can render and validate changes,
              but nothing is pushed to a device.
            </div>
          ) : view === "agent" ? (
            <div className="muted small" style={{margin:"12px 8px"}}>
              The AI Agent can inspect switches, drift, ARP conflicts, port
              errors and server metrics by calling tools against live data.
              Ask it anything about the fleet.
            </div>
          ) : view === "servers" ? (
            <React.Fragment>
              <div className="ilo-list-head">
                <span>
                  Servers ({servers.length})
                  {srvBreachCount > 0 ? (
                    <span className="pill err" style={{marginLeft:8}}>
                      {srvBreachCount} alert{srvBreachCount === 1 ? "" : "s"}
                    </span>
                  ) : null}
                </span>
                <button className="primary small" onClick={function(){ setSrvAdd(true); }}>
                  <i className="uil uil-plus" /> Add
                </button>
                <button className="secondary small" onClick={exportServers}
                        disabled={exporting || servers.length === 0}
                        title="Download every server's details and 7 days of history as an Excel workbook">
                  <i className="uil uil-file-download" /> {exporting ? "Exporting…" : "Export"}
                </button>
              </div>

              <div className="search-wrap">
                <i className="uil uil-search" />
                <input className="search-input" value={srvQ}
                       placeholder="Search servers…"
                       onChange={function(e){ setSrvQ(e.target.value); }} />
                {srvQ ? (
                  <button className="icon-btn" onClick={function(){ setSrvQ(""); }}>
                    <i className="uil uil-times" />
                  </button>
                ) : null}
              </div>

              {srvErr ? <div className="alert error">{srvErr}</div> : null}
              {servers.length === 0 ? (
                <div className="muted small" style={{padding:"10px 4px"}}>
                  No servers yet. Add HPE servers from the iLO inventory to
                  monitor CPU, memory and power.
                </div>
              ) : shownServers.length === 0 ? (
                <div className="muted small" style={{padding:"10px 4px"}}>
                  No servers match “{srvQ}”.
                </div>
              ) : null}

              {shownServers.map(function(s){
                const a  = srvAlerts[s.name] || {};
                const lv = liveAll[s.name] || {};
                const st = a.state || "unknown";
                const breach = st === "breach";
                const okState = st === "ok";
                const locked = lv.locked || _srvIsAuthError(s.last_poll_error);
                const why = breach
                  ? (a.breaches || []).map(function(b){
                      return b.sensor.replace(/_/g," ") + " " +
                             (b.kind === "upper" ? ">" : "<") + " " + b.threshold +
                             " (now " + b.value + b.unit + ")";
                    }).join("; ")
                  : locked ? "credentials rejected — click to unlock"
                  : okState ? "all thresholds respected"
                  : st === "unconfigured" ? "no thresholds set"
                  : "waiting for samples";
                return (
                  <button key={s.name}
                          className={cls("sw-row", "srv-row",
                                         srvActive === s.name && "active",
                                         breach && "breach", okState && "okthresh")}
                          title={why}
                          onClick={function(){ setSrvActive(s.name); }}>
                    <i className={"uil " + (locked ? "uil-lock"
                                  : breach ? "uil-exclamation-octagon"
                                  : "uil-server")} />
                    <div className="sw-row-info">
                      <div className="sw-row-name">{s.name}</div>
                      <div className="sw-row-meta">
                        {s.ilo_host}{s.description ? " · " + s.description : ""}
                      </div>
                      <LiveUtilBox live={lv} />
                    </div>
                    <span className="row-actions">
                      {locked ? (
                        <i className="uil uil-key-skeleton edit-ico"
                           title="Unlock — try different credentials"
                           onClick={function(e){ e.stopPropagation(); setUnlockSrv(s); }} />
                      ) : null}
                      <i className="uil uil-edit edit-ico" title="Edit server"
                         onClick={function(e){ e.stopPropagation(); setEditSrv(s); }} />
                    </span>
                    <span className={cls("thresh-dot", breach && "bad", okState && "good")}
                          title={why} />
                  </button>
                );
              })}
            </React.Fragment>
          ) : view === "links" ? (
            <div className="muted small" style={{margin:"12px 8px"}}>
              Links joins the two sides of the room: port-channels whose
              description names a server (or its iLO last octet, e.g.
              “ilo101”) are matched to that server, showing its live CPU,
              memory and jitter next to the port's traffic — plus an estimate
              of the CPU load this link's transfers are causing.
            </div>
          ) : view === "lacp" ? (
            <div className="muted small" style={{margin:"12px 8px"}}>
              LACP Configuration replaces hundreds of hand-typed CLI lines
              with one click: pick two switches, a LAG id and member ports —
              the portal validates everything (existence, membership, speed,
              admin state, duplicate LAG ids), configures both ends with a
              checkpoint taken first, shows live progress, verifies the
              bundle, and rolls back automatically on any failure.
            </div>
          ) : (
            <div className="muted small" style={{margin:"12px 8px"}}>
              The IP Conflicts view scans the latest ARP captures across every
              switch. It refreshes automatically every 20 seconds.
            </div>
          )}
        </aside>

        <main className="main">
          {view === "conflicts" ? <IpConflictsView switches={props.switches || []} /> : null}
          {view === "servers" ? (
            <ServersView servers={servers} active={srvActive}
                         alerts={srvAlerts} liveAll={liveAll}
                         reload={loadServers}
                         onEdit={function(s){ setEditSrv(s); }}
                         onUnlock={function(s){ setUnlockSrv(s); }} />
          ) : null}
          {view === "links" ? <LinkInsightsView switches={switches} /> : null}
          {view === "lacp" ? <LacpConfigView switches={switches} /> : null}
          {view === "config" ? <ConfigView switches={switches} /> : null}
          {view === "agent" ? <AgentView activeSwitch={active} /> : null}

          {showSwImport ? (
            <AddSwitchInventoryDialog
              onClose={function(){ setSwImp(false); }}
              onImported={function(){ setSwImp(false); reloadSwitches(); }} />
          ) : null}
          {editSw ? (
            <EditDialog kind="switch" item={editSw}
                        onClose={function(){ setEditSw(null); }}
                        onSaved={function(newName){
                          setEditSw(null); setActive(newName);
                          reloadSwitches();
                        }} />
          ) : null}
          {view === "switches" && !activeSw ? (
            <div className="muted" style={{padding:"20px"}}>Dashboard ready. Select a switch from the left to unlock and manage it, or use Add switch to onboard a new device.</div>
          ) : null}
          {view === "switches" && activeSw && tokens[activeSw.name] ? (
            <SwitchPanel
              sw={activeSw}
              username={usernames[activeSw.name]}
              onLock={function(){ lockSwitch(activeSw.name); }}
              onDeleted={function(name){
                removeTokenFor(name);            // drop the deleted switch's token
                if (reloadSwitches) reloadSwitches();   // refresh the sidebar list
                setActive(null);                 // clear selection (switch is gone)
                forceUpdate();                   // re-render
              }}
            />
          ) : null}
          {view === "switches" && activeSw && !tokens[activeSw.name] ? (
            <LockedSwitchPanel
              sw={activeSw}
              onUnlockClick={function(){ setUnlock(activeSw); }}
              onDeleted={function(name){
                removeTokenFor(name);
                if (reloadSwitches) reloadSwitches();
                setActive(null);
                forceUpdate();
              }}
            />
          ) : null}
        </main>
      </div>

      {unlockSw ? (
        <UnlockPrompt
          sw={unlockSw}
          onClose={function(){ setUnlock(null); }}
          onUnlocked={function(){ setUnlock(null); forceUpdate(); }}
        />
      ) : null}

      {showAdd ? (
        <AddSwitchDialog
          onClose={function(){ setShowAdd(false); }}
          onCreated={function(){ setShowAdd(false); reloadSwitches(); }}
        />
      ) : null}

      {showSrvAdd ? (
        <AddServerDialog
          onClose={function(){ setSrvAdd(false); }}
          onCreated={function(){ setSrvAdd(false); loadServers(); }} />
      ) : null}

      {editSrv ? (
        <EditDialog kind="server" item={editSrv}
                    onClose={function(){ setEditSrv(null); }}
                    onSaved={function(newName){
                      setEditSrv(null); setSrvActive(newName); loadServers();
                    }} />
      ) : null}

      {unlockSrv ? (
        <UnlockServerDialog server={unlockSrv}
                            onClose={function(){ setUnlockSrv(null); }}
                            onUnlocked={function(){
                              setUnlockSrv(null); loadServers();
                            }} />
      ) : null}

      <ChatbotWidget focusSwitch={view === "switches" && activeSw ? activeSw.name : null} />
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// IpConflictsView — system-wide view of ARP conflicts
// ────────────────────────────────────────────────────────────────────
function IpConflictsView(props) {
  const switches = props.switches || [];
  const [data, setData] = useState(null);
  const [err, setErr]   = useState("");
  const [busy, setBusy] = useState(false);
  const [autoTriggered, setAutoTriggered] = useState(false);

  const load = useCallback(async function() {
    try {
      const d = await api("/api/ip-conflicts");
      setData(d); setErr("");
    } catch (e) { setErr(e.message); }
  }, []);

  async function captureArpAll() {
    setBusy(true); setErr("");
    try {
      const r = await api("/api/arp/capture-all", { method: "POST" });
      // Show a brief summary
      const ok = r.results.filter(function(x){ return x.entries_captured != null; });
      const fail = r.results.filter(function(x){ return x.error; });
      const skipped = r.results.filter(function(x){ return x.skipped; });
      if (fail.length || skipped.length) {
        setErr(`Captured ARP from ${ok.length} switch(es). ${fail.length} failed, ${skipped.length} skipped (locked switches). First failure: ${fail[0] ? fail[0].error : "—"}`);
      }
      await load();
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  useEffect(function(){ load(); }, [load]);

  // When the view opens: if ARP data is >10 min old (or missing), kick off a
  // background capture so the table is fresh, not 6 hours stale. Runs once.
  useEffect(function() {
    if (!data || autoTriggered) return;
    const newest = (data.all_entries && data.all_entries.length > 0)
      ? Math.max.apply(null, data.all_entries.map(function(e){
          return new Date(e.captured_at).getTime(); }))
      : 0;
    const ageMs = Date.now() - newest;
    if (newest === 0 || ageMs > 10 * 60 * 1000) {
      setAutoTriggered(true);
      setBusy(true);
      api("/api/arp/capture-all", { method: "POST" })
        .then(function(){ return load(); })
        .catch(function(e){ console.warn("[ARP auto-refresh]", e.message); })
        .finally(function(){ setBusy(false); });
    }
  }, [data, autoTriggered, load]);

  // Lightweight DB re-read every 20s
  useEffect(function() {
    const t = setInterval(load, 20000);
    return function(){ clearInterval(t); };
  }, [load]);

  // Group all_entries by switch + compute which switches have NO ARP data
  const entriesBySwitch = useMemo(function() {
    const map = {};
    if (data && data.all_entries) {
      data.all_entries.forEach(function(e) {
        (map[e.switch_name] = map[e.switch_name] || []).push(e);
      });
    }
    return map;
  }, [data]);

  const switchCoverage = useMemo(function() {
    if (!switches.length) return [];
    return switches.map(function(sw) {
      const ents = entriesBySwitch[sw.name] || [];
      const newest = ents.length
        ? Math.max.apply(null, ents.map(function(e){ return new Date(e.captured_at).getTime(); }))
        : 0;
      return { name: sw.name, count: ents.length,
               newest: newest ? new Date(newest).toISOString() : null,
               has_data: ents.length > 0 };
    });
  }, [switches, entriesBySwitch]);

  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-id">
          <i className="uil uil-exclamation-triangle" />
          <div>
            <div className="panel-title">IP Conflicts & ARP Table</div>
            <div className="panel-sub">
              Conflicts surface IPs with multiple MACs. The full ARP table
              below is shown unconditionally.
            </div>
          </div>
        </div>
        <div className="panel-id-right">
          <button className="primary small" onClick={captureArpAll} disabled={busy}>
            <i className="uil uil-cloud-download" /> {busy ? "Capturing ARP…" : "Capture ARP from all switches"}
          </button>
          <button className="secondary small" onClick={load}>
            <i className="uil uil-refresh" /> Refresh
          </button>
        </div>
      </div>
      <div className="tab-body">
        {err ? <div className="alert error">{err}</div> : null}
        {data ? (
          <React.Fragment>
            <div className="muted small">
              Scanned {data.switches_scanned} switch(es) · {data.unique_ips} unique IPs ·
              {data.total_entries != null ? " " + data.total_entries + " ARP entries ·" : ""}
              checked {data.checked_at ? istTime(data.checked_at) : "—"}
              {busy ? <span style={{color:"#2563eb"}}> · refreshing…</span> : null}
            </div>

            {switchCoverage.length > 0 ? (
              <div style={{display:"flex", flexWrap:"wrap", gap:6, margin:"10px 0"}}>
                {switchCoverage.map(function(sw) {
                  return (
                    <div key={sw.name} style={{
                      padding:"4px 9px", borderRadius:6, fontSize:11.5,
                      border:"1px solid " + (sw.has_data ? "#6ee7b7" : "#fca5a5"),
                      background: sw.has_data ? "#f0fdf4" : "#fef2f2",
                      color: sw.has_data ? "#065f46" : "#991b1b" }}>
                      <b>{sw.name}</b>{" "}
                      <span style={{opacity:0.75}}>
                        {sw.has_data
                          ? sw.count + " entries · " + ago(sw.newest)
                          : "no ARP data"}
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : null}

            {data.conflicts.length > 0 ? (
              <React.Fragment>
                <div className="section-title">
                  <i className="uil uil-exclamation-triangle" style={{color:"var(--err)"}} />
                  Detected conflicts ({data.conflicts.length})
                </div>
                {data.conflicts.map(function(c) {
                  return (
                    <div key={c.ip} className="conflict-card">
                      <div className="conflict-head">
                        <i className="uil uil-exclamation-circle"
                           style={{color:"var(--err)", fontSize:20}} />
                        <span className="conflict-ip">{c.ip}</span>
                        <span className="pill err">{c.mac_count} distinct MACs</span>
                      </div>
                      <div className="table-wrap" style={{maxHeight:"none"}}>
                        <table>
                          <thead>
                            <tr>
                              <th>Switch</th>
                              <th>MAC</th>
                              <th>Interface</th>
                              <th>VLAN</th>
                              <th>Seen</th>
                            </tr>
                          </thead>
                          <tbody>
                            {c.entries.map(function(e, i) {
                              return (
                                <tr key={i}>
                                  <td>{e.switch_name}</td>
                                  <td><code>{e.mac}</code></td>
                                  <td>{e.interface || "—"}</td>
                                  <td>{e.vlan || "—"}</td>
                                  <td className="muted small">{ago(e.captured_at)}</td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })}
              </React.Fragment>
            ) : (
              <div style={{marginTop:12, padding:"10px 12px",
                          background:"#d1fae5", border:"1px solid #6ee7b7",
                          borderRadius:6, color:"#047857", fontSize:13}}>
                <i className="uil uil-check-circle" />&nbsp;
                No IP conflicts detected. Showing every ARP entry from the latest captures.
              </div>
            )}

            {/* Always show full ARP table, grouped by switch */}
            <div className="section-title">
              <i className="uil uil-list-ul" />
              All ARP entries ({data.all_entries ? data.all_entries.length : 0})
            </div>
            {data.all_entries && data.all_entries.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Switch</th>
                      <th>IP</th>
                      <th>MAC</th>
                      <th>Interface</th>
                      <th>VLAN</th>
                      <th>Type</th>
                      <th>Captured</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.all_entries.map(function(e, i) {
                      return (
                        <tr key={i}>
                          <td>{e.switch_name}</td>
                          <td><code>{e.ip}</code></td>
                          <td><code>{e.mac}</code></td>
                          <td>{e.interface || "—"}</td>
                          <td>{e.vlan || "—"}</td>
                          <td><span className="pill">{e.type || "—"}</span></td>
                          <td className="muted small">{ago(e.captured_at)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="muted" style={{marginTop:8, padding:"14px 16px",
                                              background:"var(--panel-2)",
                                              border:"1px solid var(--border)",
                                              borderRadius:8}}>
                <i className="uil uil-info-circle" />&nbsp;
                No ARP entries have been captured yet. Click
                <strong> "Capture ARP from all switches"</strong> above to
                pull <code>display arp</code> (Comware) or <code>show arp</code>
                (Aruba) from every unlocked switch and populate this view.
              </div>
            )}
          </React.Fragment>
        ) : <div className="muted">Loading…</div>}
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// ChatbotWidget — floating bottom-right RAG chat panel
// ────────────────────────────────────────────────────────────────────
function ChatbotWidget(props) {
  const focusSwitch = props.focusSwitch;
  const [open, setOpen]       = useState(false);
  const [msgs, setMsgs]       = useState(() => [
    { role: "system", content: "Ask me about config drift, IP conflicts, port traffic, or anything in your switch fleet." },
  ]);
  const [input, setInput]     = useState("");
  const [busy, setBusy]       = useState(false);
  const [status, setStatus]   = useState(null);
  const scroller = React.useRef(null);

  useEffect(function() {
    if (open) {
      fetch(API + "/api/chat/status")
        .then(function(r){ return r.json(); })
        .then(setStatus)
        .catch(function(e){ setStatus({ok:false, error: e.message || "unreachable"}); });
    }
  }, [open]);

  useEffect(function() {
    if (scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight;
  }, [msgs]);

  // A command failed somewhere in the portal: open, explain, and recommend
  // the right commands. Suggestions come from the structured advisor (allow-
  // list validated JSON with a self-correcting retry loop), so every Apply
  // button below is guaranteed to hold a real, read-only command.
  useEffect(function() {
    async function onFailed(ev) {
      const d = ev.detail || {};
      if (!d.switch || !d.command) return;
      setOpen(true);
      setMsgs(function(m){ return m.concat([{
        role: "user",
        content: "This failed on " + d.switch + ": `" + d.command + "`",
      }]); });
      setBusy(true);
      try {
        const r = await api("/api/switches/" + encodeURIComponent(d.switch) +
                            "/suggest-command",
          { method: "POST", body: JSON.stringify({
              command: d.command, error: d.error || "",
              output: d.output || "", use_model: true }) }, d.switch);
        const intro = r.explanation
          ? r.explanation
          : r.is_syntax_error
            ? "`" + d.command + "` isn't valid on " + d.switch +
              " (" + r.device_type + "). Here's what you probably meant:"
            : "That command failed on " + d.switch +
              ". Here are supported commands you can run instead:";
        setMsgs(function(m){ return m.concat([{
          role: "assistant",
          content: intro,
          suggestions: (r.suggestions || []).slice(0, 4),
          switch: d.switch,
          meta: r.model_attempts
            ? "structured output · validated in " + r.model_attempts +
              " attempt" + (r.model_attempts === 1 ? "" : "s")
            : "deterministic match (model unavailable)",
        }]); });
      } catch (e2) {
        setMsgs(function(m){ return m.concat([{
          role: "assistant",
          content: "I couldn't fetch suggestions for that failure: " +
                   (e2.message || String(e2)),
        }]); });
      } finally {
        setBusy(false);
      }
    }
    window.addEventListener("noc-command-failed", onFailed);
    return function(){ window.removeEventListener("noc-command-failed", onFailed); };
  }, []);

  // Apply: put the recommended command into the command bar of that switch.
  // Deliberately does not run it — the operator stays in the loop.
  function applyCommand(swName, cmd) {
    window.dispatchEvent(new CustomEvent("noc-apply-command", {
      detail: { switch: swName, command: cmd },
    }));
    setMsgs(function(m){ return m.concat([{
      role: "system",
      content: "Applied `" + cmd + "` to the command bar on " + swName +
               " — press Send there to run it.",
    }]); });
  }

  async function send(e) {
    if (e) e.preventDefault();
    const q = input.trim();
    if (!q || busy) return;
    setInput("");
    setMsgs(function(m){ return m.concat([{role:"user", content:q}]); });
    setBusy(true);
    try {
      const r = await fetch(API + "/api/chat/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q, switch: focusSwitch || null }),
      });
      let d = null;
      try { d = await r.json(); } catch { d = null; }
      if (!r.ok) {
        const detail = (d && d.detail) || r.statusText || ("HTTP " + r.status);
        setMsgs(function(m){ return m.concat([{
          role:"assistant",
          content:"Error: " + detail,
        }]); });
      } else {
        const metaParts = ["model=" + d.model];
        if (d.context_sections && d.context_sections.length) {
          metaParts.push("context=" + d.context_sections.join(","));
        }
        if (d.warning) metaParts.push("warning=" + d.warning);
        setMsgs(function(m){ return m.concat([{
          role:"assistant",
          content: d.answer,
          meta: metaParts.join(" · "),
        }]); });
      }
    } catch (e2) {
      // Tell the user EXACTLY what failed and which URL we tried
      setMsgs(function(m){ return m.concat([{
        role:"assistant",
        content: "Could not reach the chat endpoint at " + API + "/api/chat/query.\n"
                 + "Error: " + (e2.message || String(e2))
                 + "\n\nCheck that the backend container is healthy "
                 + "(curl " + API + "/api/chat/status) and that it can route "
                 + "to your Ollama server.",
      }]); });
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <button className="chat-fab" onClick={function(){ setOpen(true); }} title="Open AI assistant">
        <i className="uil uil-robot" />
      </button>
    );
  }

  // Header status line
  let statusEl;
  if (!status) {
    statusEl = "connecting…";
  } else if (status.ok) {
    statusEl = (
      <React.Fragment>
        <span className="dot ok" />
        &nbsp;{status.chosen_model || status.configured_model}
        {status.warning ? <span className="muted"> · {status.warning}</span> : null}
      </React.Fragment>
    );
  } else {
    statusEl = (
      <React.Fragment>
        <span className="dot warn" />
        &nbsp;Ollama issue: {status.error || "unreachable"}
      </React.Fragment>
    );
  }

  return (
    <div className="chat-panel">
      <div className="chat-head">
        <i className="uil uil-robot" />
        <div style={{minWidth:0, flex:1}}>
          <div className="chat-title">NOC Assistant</div>
          <div className="chat-sub" style={{whiteSpace:"nowrap", overflow:"hidden",
                                            textOverflow:"ellipsis"}}>
            {statusEl}
            {focusSwitch ? " · focus: " + focusSwitch : ""}
          </div>
        </div>
        <button className="icon-btn" onClick={function(){ setOpen(false); }}>
          <i className="uil uil-times" />
        </button>
      </div>

      <div className="chat-body" ref={scroller}>
        {msgs.map(function(m, i) {
          return (
            <div key={i}>
              {m.role === "user"
                ? <div className={"chat-msg " + m.role}>{m.content}</div>
                : <div className={"chat-msg " + m.role}
                       dangerouslySetInnerHTML={renderChat(m.content)} />}
              {m.suggestions && m.suggestions.length ? (
                <div className="chat-suggestions">
                  {m.suggestions.map(function(sg){
                    return (
                      <div key={sg.command} className={"chat-sg c-" + sg.confidence}
                           title={sg.reason}>
                        <div className="chat-sg-info">
                          <code>{sg.command}</code>
                          <span className="chat-sg-label">{sg.label}</span>
                        </div>
                        <button className="primary small"
                                onClick={function(){ applyCommand(m.switch, sg.command); }}>
                          Apply
                        </button>
                      </div>
                    );
                  })}
                </div>
              ) : null}
              {m.meta ? <div className="chat-meta">{m.meta}</div> : null}
            </div>
          );
        })}
        {busy ? <div className="chat-msg system">thinking…</div> : null}
      </div>

      <form className="chat-input" onSubmit={send}>
        <input value={input} placeholder="Ask about drift, ports, conflicts…"
               onChange={function(e){ setInput(e.target.value); }} disabled={busy} />
        <button type="submit" className="primary" disabled={busy || !input.trim()}>Send</button>
      </form>
    </div>
  );
}


function App() {
  const [switches, setSwitches] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [loggedIn, setLoggedIn] = useState(true);
  const [bootErr, setBootErr]   = useState("");
  const [showAddSwitch, setShowAddSwitch] = useState(false);

  const reload = useCallback(async function() {
    setLoading(true);
    try {
      const list = await api("/api/switches");
      setSwitches(list || []);
      setBootErr("");
    } catch (e) {
      setBootErr("Cannot reach API at " + API + ": " + e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(function(){ reload(); }, [reload]);

  useEffect(function() {
    function handler() { setLoggedIn(true); }
    window.addEventListener("storage", handler);
    return function(){ window.removeEventListener("storage", handler); };
  }, []);
async function onLogoutAll() {
    if (!window.confirm("End your NOC Portal session and return to login?")) return;

    const seen = new Set();
    Object.values(getTokens()).forEach(function(t) {
      if (seen.has(t)) return;
      seen.add(t);
      fetch(API + "/api/admin/logout", {
        method: "POST",
        headers: { "X-Admin-Token": t },
        credentials: "include",
      }).catch(function(){});
    });

    try {
      await fetch(API + "/api/noc/portal/logout", {
        method: "POST",
        credentials: "include",
      });
    } catch (e) {}

    clearAllTokens();
    window.location.href = "/login";
  }


  if (bootErr) {
    return (
      <div className="boot-error">
        <i className="uil uil-exclamation-triangle" />
        <div>
          <h2>Backend not reachable</h2>
          <div className="muted">{bootErr}</div>
          <button className="primary" style={{ marginTop: 14 }} onClick={reload}>Retry</button>
        </div>
      </div>
    );
  }

  if (false && !loggedIn) {
    return null
  }

  return (
    <Dashboard
      switches={switches}
      reloadSwitches={reload}
      onLogoutAll={onLogoutAll}
    />
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);