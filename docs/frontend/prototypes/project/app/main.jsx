/* koopa.admin — app root: routing, command palette, toasts, tweaks */
const { useState: aS, useEffect: aE, useCallback: aC } = React;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "density": "regular",
  "accent": ["#2BB6C4"],
  "nav": "expanded",
  "todayState": "populated"
}/*EDITMODE-END*/;

// accent option -> token overrides (kept within the system's restrained palette)
const ACCENTS = {
  "#2BB6C4": { brand: "oklch(0.72 0.10 210)", strong: "oklch(0.64 0.12 210)", muted: "oklch(0.72 0.10 210 / 0.14)", faint: "oklch(0.72 0.10 210 / 0.06)" }, // cyan-teal (default)
  "#4F8DF5": { brand: "oklch(0.68 0.13 250)", strong: "oklch(0.60 0.14 250)", muted: "oklch(0.68 0.13 250 / 0.14)", faint: "oklch(0.68 0.13 250 / 0.06)" }, // cool blue
  "#3FB98C": { brand: "oklch(0.72 0.11 168)", strong: "oklch(0.64 0.12 168)", muted: "oklch(0.72 0.11 168 / 0.14)", faint: "oklch(0.72 0.11 168 / 0.06)" }, // teal-green
};

function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [route, setRoute] = aS("today");
  const [cmdk, setCmdk] = aS(false);
  const [toasts, setToasts] = aS([]);

  const toast = aC((msg, icon, kind) => {
    const id = Date.now() + Math.random();
    setToasts((xs) => [...xs, { id, msg, icon, kind }]);
    setTimeout(() => setToasts((xs) => xs.filter((x) => x.id !== id)), 2600);
  }, []);

  const go = aC((r) => {
    if (r === "@cmdk") { setCmdk(true); return; }
    setRoute(r); setCmdk(false);
  }, []);

  // ⌘K / Ctrl-K
  aE(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setCmdk((o) => !o); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const accent = ACCENTS[Array.isArray(t.accent) ? t.accent[0] : t.accent] || ACCENTS["#2BB6C4"];
  const shellStyle = {
    "--brand": accent.brand, "--brand-strong": accent.strong,
    "--brand-muted": accent.muted, "--brand-faint": accent.faint,
  };

  const screen = () => {
    const [base, arg] = route.split(":");
    switch (base) {
      case "today": return <TodayScreen dataState={t.todayState} go={go} toast={toast} />;
      case "goals": return <GoalsList go={go} toast={toast} />;
      case "goal-new": return <GoalNew go={go} toast={toast} />;
      case "goal": return <GoalDetail go={go} toast={toast} />;
      case "plans": return <PlansList go={go} toast={toast} />;
      case "plan-new": return <PlanNew go={go} toast={toast} />;
      case "plan-detail": return <PlanDetail go={go} toast={toast} />;
      case "inbox": return <GTD key="gtd-inbox" go={go} toast={toast} initialTab="inbox" />;
      case "todos": return <GTD key="gtd-todos" go={go} toast={toast} initialTab="today" />;
      case "content": return <ContentList go={go} toast={toast} />;
      case "content-editor": return <ContentEditor key={arg} id={arg} go={go} toast={toast} />;
      case "notes": return <NoteList go={go} toast={toast} />;
      case "note-editor": return <NoteEditor key={arg} id={arg} go={go} toast={toast} />;
      case "learning": return <LearningDashboard go={go} toast={toast} />;
      default: return <Stub route={base} go={go} />;
    }
  };

  return (
    <div className="admin-shell" data-density={t.density} data-nav={t.nav} style={shellStyle} data-screen-label={route}>
      <Sidebar route={route} go={go} />
      <div className="workspace">{screen()}</div>

      <CommandPalette open={cmdk} onClose={() => setCmdk(false)} go={go} toast={toast} />
      <ToastHost toasts={toasts} />

      <TweaksPanel>
        <TweakSection label="Density" />
        <TweakRadio label="Row density" value={t.density} options={["compact", "regular", "comfortable"]} onChange={(v) => setTweak("density", v)} />
        <TweakSection label="Accent" />
        <TweakColor label="Brand accent" value={t.accent} options={["#2BB6C4", "#4F8DF5", "#3FB98C"]} onChange={(v) => setTweak("accent", v)} />
        <TweakSection label="Navigation" />
        <TweakRadio label="Sidebar" value={t.nav} options={["expanded", "collapsed"]} onChange={(v) => setTweak("nav", v)} />
        <TweakSection label="Today — data state" />
        <TweakRadio label="State" value={t.todayState} options={["populated", "loading", "empty", "error"]} onChange={(v) => { setTweak("todayState", v); setRoute("today"); }} />
      </TweaksPanel>
    </div>
  );
}

/* Plans list (small, lives here) */
function PlansList({ go }) {
  const rows = [
    { id: "lp_04A", title: K.plan.plan.title, domain: "system-design", status: "active", entries: 9, prog: 0.44 },
    { id: "lp_03B", title: "Go concurrency — beyond goroutines & channels", domain: "go", status: "active", entries: 7, prog: 0.71 },
    { id: "lp_02C", title: "LeetCode patterns — the 14 that matter", domain: "leetcode", status: "active", entries: 14, prog: 0.58 },
    { id: "lp_01D", title: "Reading: Designing Data-Intensive Applications", domain: "reading", status: "draft", entries: 12, prog: 0.0 },
  ];
  return (
    <div className="admin-body">
      <Topbar title="Learning plans" crumbs={["learning", "plans"]} actions={<Btn icon="plus" variant="primary" onClick={() => go("plan-new")}>New plan</Btn>} />
      <table className="content-table">
        <thead><tr><th>Title</th><th>Domain</th><th>Entries</th><th>Progress</th><th>Status</th><th>ID</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="cell-title" onClick={() => go("plan-detail")}>{r.title}</td>
              <td><span className="k-chip">{r.domain}</span></td>
              <td><span className="cell-date">{r.entries}</span></td>
              <td><div style={{ display: "flex", alignItems: "center", gap: 8 }}><div className="proj-bar" style={{ width: 80 }}><i style={{ width: (r.prog * 100) + "%" }} /></div><span className="cell-date">{Math.round(r.prog * 100)}%</span></div></td>
              <td><span className={"entry-state es-" + (r.status === "active" ? "active" : "pending")}>{r.status}</span></td>
              <td><span className="cell-id">{r.id}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
