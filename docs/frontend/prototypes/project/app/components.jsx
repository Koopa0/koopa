/* koopa.admin — shared components: icons, shell, primitives, command palette, toasts */
const { useState, useEffect, useRef, useCallback } = React;

/* ---------- Icons (Lucide-style, stroke 1.5) ---------- */
const Icon = ({ name, size = 18, stroke = 1.5, style }) => {
  const d = ICON_PATHS[name] || ICON_PATHS.dot;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round" style={style} aria-hidden="true">
      {(Array.isArray(d) ? d : [d]).map((p, i) => <path key={i} d={p} />)}
    </svg>
  );
};
const ICON_PATHS = {
  dot: "M12 12h.01",
  sunrise: ["M12 2v6", "m5 9 1.5 1.5", "M2 16h2", "M20 16h2", "m17.5 10.5 1.5-1.5", "M22 20H2", "M16 16a4 4 0 0 0-8 0"],
  listChecks: ["m3 7 2 2 4-4", "m3 17 2 2 4-4", "M13 6h8", "M13 12h8", "M13 18h8"],
  inbox: ["M22 12h-6l-2 3h-4l-2-3H2", "M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"],
  target: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 6a6 6 0 1 0 0 12 6 6 0 0 0 0-12z", "M12 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4z"],
  folder: ["M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2z"],
  layers: ["m12.83 2.18 8.31 4.16a.6.6 0 0 1 0 1.07l-8.31 4.16a2 2 0 0 1-1.66 0L2.86 7.41a.6.6 0 0 1 0-1.07l8.31-4.16a2 2 0 0 1 1.66 0z", "m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65", "m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"],
  fileText: ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6", "M9 13h6", "M9 17h4"],
  notebook: ["M2 6h4", "M2 12h4", "M2 18h4", "M6 3h12a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6z", "M11 3v18"],
  rss: ["M4 11a9 9 0 0 1 9 9", "M4 4a16 16 0 0 1 16 16", "M5 19a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"],
  hash: ["M4 9h16", "M4 15h16", "M10 3 8 21", "M16 3l-2 18"],
  search: ["M21 21l-4.3-4.3", "M11 4a7 7 0 1 1 0 14 7 7 0 0 1 0-14z"],
  brain: ["M12 5a3 3 0 1 0-5.997.142 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18z", "M12 5a3 3 0 1 1 5.997.142 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18z"],
  route: ["M6 19a3 3 0 1 0 0-6 3 3 0 0 0 0 6z", "M18 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6z", "M9 16h5a3 3 0 0 0 3-3v-2"],
  compass: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "m16.24 7.76-2.12 6.36-6.36 2.12 2.12-6.36 6.36-2.12z"],
  flask: ["M9 3h6", "M10 3v6.5L5.5 17a2 2 0 0 0 1.7 3h9.6a2 2 0 0 0 1.7-3L14 9.5V3", "M8.5 14h7"],
  globe: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M2 12h20", "M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"],
  calendarClock: ["M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h7", "M16 2v4", "M8 2v4", "M3 10h18", "M17.5 17.5 16 16.3V14", "M22 16a6 6 0 1 1-12 0 6 6 0 0 1 12 0z"],
  activity: "M22 12h-4l-3 9L9 3l-3 9H2",
  gauge: ["M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z", "m13.4 12.6 4.6-4.6", "M12 2a10 10 0 1 0 9.5 13"],
  barChart: ["M3 3v18h18", "M8 17v-5", "M13 17V8", "M18 17v-3"],
  cpu: ["M6 6h12v12H6z", "M9 2v2", "M15 2v2", "M9 20v2", "M15 20v2", "M2 9h2", "M2 15h2", "M20 9h2", "M20 15h2", "M10 10h4v4h-4z"],
  heart: ["M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7z"],
  plus: ["M12 5v14", "M5 12h14"],
  arrowRight: ["M5 12h14", "m12 5 7 7-7 7"],
  check: "m5 12 5 5L20 7",
  chevronDown: "m6 9 6 6 6-6",
  chevronRight: "m9 6 6 6-6 6",
  x: ["M18 6 6 18", "m6 6 12 12"],
  command: "M15 6a3 3 0 1 0 3 3H6a3 3 0 1 0 3-3v12a3 3 0 1 0-3-3h12a3 3 0 1 0-3 3z",
  enter: ["M9 10 4 15l5 5", "M20 4v7a4 4 0 0 1-4 4H4"],
  clock: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 6v6l4 2"],
  play: "m6 4 14 8-14 8z",
  bookmark: "m19 21-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z",
  grip: ["M9 5a1 1 0 1 0 0 2 1 1 0 0 0 0-2z", "M9 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2z", "M9 17a1 1 0 1 0 0 2 1 1 0 0 0 0-2z", "M15 5a1 1 0 1 0 0 2 1 1 0 0 0 0-2z", "M15 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2z", "M15 17a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"],
  alert: ["M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z", "M12 9v4", "M12 17h.01"],
  sparkles: ["M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z", "M19 3v4", "M21 5h-4"],
  undo: ["M3 7v6h6", "M3 13a9 9 0 1 0 3-7.7L3 8"],
  external: ["M15 3h6v6", "M10 14 21 3", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"],
  flag: ["M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z", "M4 22v-7"],
  calendar: ["M8 2v4", "M16 2v4", "M3 10h18", "M5 4h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"],
  settings: ["M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z", "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"],
  refresh: ["M3 12a9 9 0 0 1 15-6.7L21 8", "M21 3v5h-5", "M21 12a9 9 0 0 1-15 6.7L3 16", "M3 21v-5h5"],
  defer: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 8v4l3 2", "M16 4l4 2"],
};

/* ---------- Hexagon motif ---------- */
const Hexagon = ({ size = 48, stroke = 1.5, fill = "none", style }) => (
  <svg width={size} height={size} viewBox="0 0 48 48" fill={fill} stroke="currentColor"
    strokeWidth={stroke} strokeLinejoin="round" style={style} aria-hidden="true">
    <path d="M24 3.5 41.7 13.75v20.5L24 44.5 6.3 34.25v-20.5z" />
  </svg>
);

/* ---------- Primitives ---------- */
const Btn = ({ icon, children, variant = "", size = "", ...p }) => (
  <button className={"k-btn " + variant + (size ? " " + size : "")} {...p}>
    {icon && <Icon name={icon} size={size === "sm" ? 13 : 14} />}{children}
  </button>
);
const EnergyMeter = ({ level }) => (
  <span className={"energy " + level} title={"energy: " + level}><i/><i/><i/></span>
);
const StatusBadge = ({ status }) => (
  <span className={"status-badge status-" + status}><span className="dot"/>{status}</span>
);

/* ---------- Sidebar (5 IA areas) ---------- */
const NAV = [
  { group: "Daily", items: [
    { id: "today", label: "Today", icon: "sunrise" },
    { id: "plan", label: "Plan", icon: "calendar" },
    { id: "inbox", label: "GTD Inbox", icon: "inbox", count: 12 },
    { id: "todos", label: "Todos", icon: "listChecks", count: 23 },
  ]},
  { group: "Commitment", items: [
    { id: "goals", label: "Goals", icon: "target", count: 6 },
    { id: "projects", label: "Projects", icon: "folder", count: 11 },
    { id: "areas", label: "Areas", icon: "layers" },
  ]},
  { group: "Knowledge", items: [
    { id: "content", label: "Content", icon: "fileText", count: 10 },
    { id: "notes", label: "Notes", icon: "notebook", count: 84 },
    { id: "feeds", label: "Feeds", icon: "rss", count: 14 },
    { id: "tags", label: "Tags & topics", icon: "hash" },
    { id: "search", label: "Search", icon: "search" },
  ]},
  { group: "Learning", items: [
    { id: "learning", label: "Dashboard", icon: "brain" },
    { id: "sessions", label: "Sessions", icon: "calendarClock" },
    { id: "plans", label: "Plans", icon: "route", count: 4 },
    { id: "concepts", label: "Concepts", icon: "compass", count: 48 },
    { id: "hypotheses", label: "Hypotheses", icon: "flask", count: 4 },
    { id: "domains", label: "Domains", icon: "globe" },
  ]},
  { group: "System", items: [
    { id: "health", label: "Health", icon: "gauge" },
    { id: "stats", label: "Stats", icon: "barChart" },
    { id: "activity", label: "Activity", icon: "activity" },
    { id: "agents", label: "Agents", icon: "cpu", count: 4 },
  ]},
];

function Sidebar({ route, go }) {
  const baseRoute = route.split(":")[0];
  const activeFor = (id) => baseRoute === id ||
    (id === "goals" && baseRoute === "goal") || (id === "plans" && baseRoute === "plan-detail") ||
    (id === "goals" && baseRoute === "goal-new") || (id === "plans" && baseRoute === "plan-new") ||
    (id === "content" && baseRoute === "content-editor") || (id === "notes" && baseRoute === "note-editor");
  return (
    <aside className="nav-rail">
      <div className="nav-brand">
        <img src="assets/logo.png" width="22" height="22" alt="koopa" style={{ borderRadius: 4 }} />
        <div>
          <div className="nav-brand-name">koopa.admin</div>
          <div className="nav-brand-env">local · dark</div>
        </div>
      </div>
      <div style={{ overflowY: "auto", flex: 1, margin: "0 -4px", padding: "0 4px" }}>
        {NAV.map((grp) => (
          <div key={grp.group}>
            <div className="nav-group-label">{grp.group}</div>
            {grp.items.map((it) => (
              <a key={it.id} href="#" className={"nav-item" + (activeFor(it.id) ? " active" : "")}
                title={it.label}
                onClick={(e) => { e.preventDefault(); go(it.id); }}>
                <Icon name={it.icon} size={16} />
                <span>{it.label}</span>
                {it.count != null && <span className="nav-count">{it.count}</span>}
              </a>
            ))}
          </div>
        ))}
      </div>
      <div className="nav-user">
        <div className="nav-avatar">K</div>
        <div className="nav-user-info">
          <div className="nav-user-name">koopa</div>
          <div className="nav-user-status"><span className="nav-user-dot"/> 4 agents active</div>
        </div>
      </div>
    </aside>
  );
}

/* ---------- Topbar ---------- */
function Topbar({ title, crumbs, actions, onSearch }) {
  return (
    <div className="topbar">
      <div className="topbar-title">{title}</div>
      {crumbs && <div className="topbar-crumbs">{crumbs.map((c, i) => <span key={i}>{i > 0 && "/ "}{c}</span>)}</div>}
      <div className="topbar-spacer" />
      <div className="topbar-search" onClick={onSearch}>
        <Icon name="search" size={14} /><span>Search & commands…</span><kbd className="kbd">⌘K</kbd>
      </div>
      {actions}
    </div>
  );
}

/* ---------- Toasts ---------- */
function ToastHost({ toasts }) {
  return (
    <div className="toast-wrap">
      {toasts.map((t) => (
        <div className="toast" key={t.id}>
          <span className={"ic " + (t.kind || "")}><Icon name={t.icon || "check"} size={15} /></span>
          {t.msg}
        </div>
      ))}
    </div>
  );
}

/* ---------- Command palette ---------- */
function CommandPalette({ open, onClose, go, toast }) {
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef(null);
  useEffect(() => { if (open) { setQ(""); setActive(0); setTimeout(() => inputRef.current && inputRef.current.focus(), 20); } }, [open]);

  const commands = [
    { group: "Navigate", icon: "sunrise", label: "Go to Today", sub: "daily", run: () => go("today") },
    { group: "Navigate", icon: "target", label: "Go to Goals", sub: "commitment", run: () => go("goals") },
    { group: "Navigate", icon: "route", label: "Go to Learning Plans", sub: "learning", run: () => go("plans") },
    { group: "Navigate", icon: "listChecks", label: "Go to Todos", sub: "daily", run: () => go("todos") },
    { group: "Navigate", icon: "fileText", label: "Go to Content", sub: "knowledge", run: () => go("content") },
    { group: "Navigate", icon: "brain", label: "Go to Learning dashboard", sub: "learning", run: () => go("learning") },
    { group: "Create", icon: "target", label: "New goal", sub: "G then N", run: () => go("goal-new") },
    { group: "Create", icon: "route", label: "New learning plan", sub: "P then N", run: () => go("plan-new") },
    { group: "Action", icon: "play", label: "Start a learning session", sub: "system-design", run: () => { toast("Session started · Replication & consistency", "play"); } },
    { group: "Action", icon: "rss", label: "Curate RSS highlights", sub: "14 unread", run: () => go("feeds") },
  ];

  const filtered = q.trim()
    ? commands.filter((c) => (c.label + " " + c.group + " " + (c.sub || "")).toLowerCase().includes(q.toLowerCase()))
    : commands;
  const captureMode = q.trim().length > 1 && filtered.length === 0;
  const flat = captureMode
    ? [{ group: "Capture", icon: "inbox", label: `Capture “${q.trim()}” to GTD Inbox`, sub: "enter", run: () => { toast(`Captured to inbox: “${q.trim()}”`, "inbox"); } }]
    : filtered;

  const groups = [];
  flat.forEach((c) => { let g = groups.find((x) => x.group === c.group); if (!g) { g = { group: c.group, items: [] }; groups.push(g); } g.items.push(c); });

  const runIdx = useCallback((i) => { const c = flat[i]; if (c) { c.run(); onClose(); } }, [flat, onClose]);
  const onKey = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, flat.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); runIdx(active); }
    else if (e.key === "Escape") { e.preventDefault(); onClose(); }
  };
  useEffect(() => { setActive(0); }, [q]);
  if (!open) return null;
  let idx = -1;
  return (
    <div className="cmdk-scrim" onMouseDown={onClose}>
      <div className="cmdk" onMouseDown={(e) => e.stopPropagation()}>
        <div className="cmdk-input-row">
          <span className="ic"><Icon name={captureMode ? "inbox" : "search"} size={17} /></span>
          <input ref={inputRef} className="cmdk-input" placeholder="Search, navigate, or capture a todo…"
            value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} />
          {captureMode && <span className="cmdk-mode">capture</span>}
        </div>
        <div className="cmdk-list">
          {flat.length === 0 && <div className="cmdk-empty">No matches. Keep typing to capture as a todo.</div>}
          {groups.map((g) => (
            <div key={g.group}>
              <div className="cmdk-group-label">{g.group}</div>
              {g.items.map((c) => {
                idx++; const my = idx;
                return (
                  <div key={c.label} className={"cmdk-item" + (active === my ? " active" : "")}
                    onMouseEnter={() => setActive(my)} onClick={() => runIdx(my)}>
                    <span className="ic"><Icon name={c.icon} size={16} /></span>
                    <span className="label">{c.label}</span>
                    {c.sub && <span className="sub">{c.sub}</span>}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
        <div className="cmdk-foot">
          <span className="k"><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span className="k"><kbd>↵</kbd> select</span>
          <span className="k"><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { Icon, Hexagon, Btn, EnergyMeter, StatusBadge, Sidebar, Topbar, ToastHost, CommandPalette });
