/* koopa.admin — GTD Inbox / Todos (screen 4), bound to the real Todo contract */
const { useState: g3S, useEffect: g3E, useRef: g3R } = React;

const GTD_PROJECTS = ["koopa-core", "koopa-learning", "infra", "Content", "(no project)"];

function GTD({ go, toast, initialTab = "inbox" }) {
  const [items, setItems] = g3S(K.todos);
  const [tab, setTab] = g3S(initialTab);
  const [sel, setSel] = g3S(0);
  const [query, setQuery] = g3S("");
  const [capture, setCapture] = g3S("");
  const [clarify, setClarify] = g3S(null);
  const [cf, setCf] = g3S({ project: "", energy: "medium", due: "" });

  // ---- view filters (single Item shape, filtered by state/flags) ----
  const byTab = {
    inbox: items.filter((i) => i.state === "inbox"),
    today: items.filter((i) => i.in_today && i.state !== "done"),
    pending: items.filter((i) => i.state === "todo" && !i.in_today && !i.recur),
    someday: items.filter((i) => i.state === "someday"),
    recurring: items.filter((i) => i.recur && i.state !== "done"),
    history: items.filter((i) => i.state === "done" && (!query || i.title.toLowerCase().includes(query.toLowerCase()))),
  };
  const TABS = [
    { id: "inbox", label: "Inbox" }, { id: "today", label: "Today" }, { id: "pending", label: "Pending" },
    { id: "someday", label: "Someday" }, { id: "recurring", label: "Recurring" }, { id: "history", label: "History" },
  ];
  const list = byTab[tab];
  const triageable = tab !== "recurring" && tab !== "history";

  g3E(() => { setSel(0); }, [tab]);
  g3E(() => { if (sel > list.length - 1) setSel(Math.max(0, list.length - 1)); }, [list.length]);

  // ---- mutations (advance verbs: clarify / start / complete / defer / drop) ----
  const patch = (id, fields) => setItems((xs) => xs.map((i) => i.id === id ? { ...i, ...fields } : i));
  const remove = (id) => setItems((xs) => xs.filter((i) => i.id !== id));
  const openClarify = (i) => { setClarify(i); setCf({ project: "", energy: i.energy || "medium", due: "" }); };
  const confirmClarify = () => {
    patch(clarify.id, { state: "todo", project: cf.project === "(no project)" ? null : cf.project || null, energy: cf.energy, due: cf.due || null });
    toast("Clarified → todo", "check", "ok"); setClarify(null);
  };
  const advance = (i) => {
    if (i.state === "inbox") { openClarify(i); return; }
    if (i.state === "todo") { patch(i.id, { state: "in_progress" }); toast("Started", "play"); return; }
    if (i.state === "in_progress") { patch(i.id, { state: "done", in_today: false, completed_at: "just now" }); toast("Completed", "check", "ok"); return; }
    if (i.state === "someday") { patch(i.id, { state: "todo" }); toast("Activated → todo", "check"); return; }
  };
  const defer = (i) => { patch(i.id, { state: "someday", in_today: false }); toast("Deferred → someday", "defer"); };
  const drop = (i) => { remove(i.id); toast("Dropped", "x"); };
  const pull = (i) => { patch(i.id, { in_today: !i.in_today }); toast(i.in_today ? "Removed from today" : "Pulled into today", "calendar"); };

  // ---- keyboard triage ----
  const stateRef = g3R();
  stateRef.current = { list, sel, triageable, tab };
  g3E(() => {
    const onKey = (e) => {
      const a = document.activeElement;
      if (a && (a.tagName === "INPUT" || a.tagName === "TEXTAREA" || a.tagName === "SELECT")) return;
      if (document.querySelector(".scrim")) return;
      const s = stateRef.current; const cur = s.list[s.sel];
      if (e.key === "j" || e.key === "ArrowDown") { e.preventDefault(); setSel((x) => Math.min(x + 1, s.list.length - 1)); }
      else if (e.key === "k" || e.key === "ArrowUp") { e.preventDefault(); setSel((x) => Math.max(x - 1, 0)); }
      else if (!s.triageable || !cur) { return; }
      else if (e.key === "e" || e.key === "Enter") { e.preventDefault(); advance(cur); }
      else if (e.key === "c" && s.tab === "inbox") { e.preventDefault(); openClarify(cur); }
      else if (e.key === "d") { e.preventDefault(); defer(cur); }
      else if (e.key === "x") { e.preventDefault(); drop(cur); }
      else if (e.key === "t" && (s.tab === "pending" || s.tab === "someday")) { e.preventDefault(); pull(cur); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const addCapture = () => {
    const t = capture.trim(); if (!t) return;
    setItems((xs) => [{ id: "td_n" + Date.now(), title: t, state: "inbox", created_by: "human", age: "now" }, ...xs]);
    setCapture(""); setTab("inbox"); setSel(0); toast("Captured to inbox", "inbox");
  };

  const energyOf = (i) => i.energy && <EnergyMeter level={i.energy} />;
  const projChip = (i) => i.project ? <span className="k-chip"><span className="dot" style={{ background: "var(--brand)" }} />{i.project}</span> : <span className="k-chip" style={{ color: "var(--fg-faint)" }}>{i.area || "unfiled"}</span>;
  const dueChip = (i) => i.due && <span className={"due-chip " + (String(i.due).includes("overdue") ? "overdue" : String(i.due) === "today" ? "soon" : "")}>{i.due}</span>;

  // ---- row renderers ----
  const Row = ({ i, idx }) => (
    <div className={"row gtd-row" + (triageable && idx === sel ? " sel" : "")} onMouseEnter={() => triageable && setSel(idx)} onClick={() => triageable && setSel(idx)}>
      {tab === "inbox" ? (
        <>
          <span className="gtd-source"><Icon name={i.created_by === "system" ? "rss" : "inbox"} size={14} /></span>
          <span className="r-title">{i.title}</span>
          <div className="r-meta">
            <span className="k-chip" style={{ color: "var(--fg-faint)" }}>{i.source || i.created_by}</span>
            <span className="cell-date">{i.age}</span>
            <div className="acts">
              <Btn size="sm" variant="primary" icon="check" onClick={() => openClarify(i)}>Clarify</Btn>
              <Btn size="sm" variant="ghost" icon="defer" onClick={() => defer(i)} title="Defer (d)" />
              <Btn size="sm" variant="ghost" icon="x" onClick={() => drop(i)} title="Drop (x)" />
            </div>
          </div>
        </>
      ) : tab === "history" ? (
        <>
          <div className="check done" style={{ cursor: "default" }}><Icon name="check" size={11} stroke={2.5} /></div>
          <span className="r-title" style={{ color: "var(--fg-muted)" }}>{i.title}</span>
          <div className="r-meta">{projChip(i)}<span className="cell-date">{i.completed_at}</span></div>
        </>
      ) : (
        <>
          <div className={"check" + (i.state === "done" ? " done" : "")} onClick={(e) => { e.stopPropagation(); advance(i); }} title="advance (e)">
            {i.state === "in_progress" && <span style={{ width: 7, height: 7, borderRadius: 2, background: "var(--info)" }} />}
          </div>
          <span className="r-title">{i.title}</span>
          <div className="r-meta">
            {i.recur && <span className="k-chip" style={{ color: "var(--fg-subtle)" }}><Icon name="refresh" size={11} />every {i.recur}</span>}
            {i.state === "in_progress" && <span className="tstate in_progress">in progress</span>}
            {projChip(i)}
            {energyOf(i)}
            {dueChip(i)}
            <div className="acts">
              {i.state === "someday"
                ? <Btn size="sm" icon="arrowRight" onClick={() => advance(i)}>Activate</Btn>
                : <Btn size="sm" icon={i.state === "in_progress" ? "check" : "play"} onClick={() => advance(i)}>{i.state === "in_progress" ? "Complete" : "Start"}</Btn>}
              {(tab === "pending" || tab === "someday") && <Btn size="sm" variant="ghost" icon="calendar" onClick={() => pull(i)} title="Pull into today (t)" />}
              {i.state !== "someday" && <Btn size="sm" variant="ghost" icon="defer" onClick={() => defer(i)} title="Defer (d)" />}
              <Btn size="sm" variant="ghost" icon="x" onClick={() => drop(i)} title="Drop (x)" />
            </div>
          </div>
        </>
      )}
    </div>
  );

  const emptyCopy = {
    inbox: ["Inbox zero", "Nothing to clarify. Captures land here — clear them into todos, someday, or the bin."],
    today: ["Nothing pulled into today", "Pull pending todos in with t, or plan your day from the Plan view."],
    pending: ["No clarified todos waiting", "Clarify something from the inbox and it shows up here."],
    someday: ["No someday/maybe", "Things you might do, but not now. Defer with d to park them here."],
    recurring: ["No recurring todos", "Recurring routines surface here when they’re due."],
    history: ["No history yet", query ? "No completed todos match your search." : "Completed todos are kept here."],
  };

  return (
    <div className="admin-body" style={{ display: "flex", flexDirection: "column" }}>
      <Topbar title="Todos" crumbs={["daily", tab]} onSearch={() => go("@cmdk")} actions={
        <Btn icon="plus" variant="primary" onClick={() => document.getElementById("gtd-capture").focus()}>Capture</Btn>
      } />

      <div className="gtd-cap">
        <Icon name="plus" size={16} style={{ color: "var(--fg-subtle)" }} />
        <input id="gtd-capture" value={capture} placeholder="Capture a thought — it lands in the inbox, unclarified…"
          onChange={(e) => setCapture(e.target.value)} onKeyDown={(e) => e.key === "Enter" && addCapture()} />
        <kbd className="kbd">↵ capture</kbd>
      </div>

      <div className="content-toolbar" style={{ position: "static" }}>
        <div className="content-chips">
          {TABS.map((t) => (
            <button key={t.id} className={"filter-chip" + (tab === t.id ? " active" : "")} onClick={() => setTab(t.id)}>
              {t.label}<span style={{ marginLeft: 6, opacity: 0.7 }}>{byTab[t.id].length}</span>
            </button>
          ))}
        </div>
        {tab === "history" && (
          <div className="topbar-search" style={{ marginLeft: "auto", minWidth: 200 }}>
            <Icon name="search" size={13} />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search history…"
              style={{ background: "transparent", border: "none", outline: "none", color: "var(--fg)", font: "inherit", fontSize: 12, width: "100%" }} />
          </div>
        )}
      </div>

      <div style={{ flex: 1, overflow: "auto" }}>
        {tab === "recurring" ? (
          ["due_today", "overdue"].map((bucket) => {
            const rows = list.filter((i) => i.recur_bucket === bucket);
            if (!rows.length) return null;
            return (
              <div key={bucket}>
                <div className="gtd-group">{bucket === "due_today" ? "Due today" : "Overdue"} <span>{rows.length}</span></div>
                {rows.map((i) => <Row key={i.id} i={i} idx={list.indexOf(i)} />)}
              </div>
            );
          })
        ) : list.length ? (
          list.map((i, idx) => <Row key={i.id} i={i} idx={idx} />)
        ) : (
          <div className="state-empty" style={{ padding: "60px 20px" }}>
            <span className="hex"><Hexagon size={48} /></span>
            <h4>{emptyCopy[tab][0]}</h4><p>{emptyCopy[tab][1]}</p>
          </div>
        )}
      </div>

      <div className="kbar">
        <span className="kgrp"><kbd>j</kbd><kbd>k</kbd> move</span>
        {triageable && <>
          <span className="kgrp"><kbd>e</kbd> {tab === "inbox" ? "clarify" : "advance"}</span>
          {tab === "inbox" && <span className="kgrp"><kbd>c</kbd> clarify</span>}
          <span className="kgrp"><kbd>d</kbd> defer</span>
          {(tab === "pending" || tab === "someday") && <span className="kgrp"><kbd>t</kbd> pull to today</span>}
          <span className="kgrp"><kbd>x</kbd> drop</span>
        </>}
        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", color: "var(--fg-faint)" }}>{list.length} item{list.length === 1 ? "" : "s"}</span>
      </div>

      {clarify && (
        <div className="scrim" onMouseDown={() => setClarify(null)}>
          <div className="dialog" onMouseDown={(e) => e.stopPropagation()}>
            <div className="dialog-head">
              <span className="gate-req" style={{ color: "var(--brand)" }}><Icon name="inbox" size={12} />clarify capture</span>
              <h3 style={{ marginTop: 6 }}>{clarify.title}</h3>
              <p>Give it just enough shape to act on — project, energy, when. It becomes a <span className="k-mono" style={{ color: "var(--fg-muted)" }}>todo</span>.</p>
            </div>
            <div className="dialog-body">
              <div className="field" style={{ margin: 0 }}>
                <span className="field-label">Project</span>
                <select className="field-select" value={cf.project} onChange={(e) => setCf({ ...cf, project: e.target.value })}>
                  <option value="">Select a project…</option>
                  {GTD_PROJECTS.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div className="field" style={{ margin: 0 }}>
                <span className="field-label">Energy</span>
                <div className="seg">
                  {["low", "medium", "high"].map((lv) => (
                    <button key={lv} className={cf.energy === lv ? "active" : ""} onClick={() => setCf({ ...cf, energy: lv })}>{lv}</button>
                  ))}
                </div>
              </div>
              <div className="field" style={{ margin: 0, maxWidth: 220 }}>
                <span className="field-label">Due <span className="opt">— optional</span></span>
                <input className="field-input" type="date" value={cf.due} onChange={(e) => setCf({ ...cf, due: e.target.value })} />
              </div>
            </div>
            <div className="dialog-foot">
              <Btn variant="ghost" icon="defer" onClick={() => { defer(clarify); setClarify(null); }}>Defer instead</Btn>
              <span className="spacer" />
              <Btn onClick={() => setClarify(null)}>Cancel</Btn>
              <Btn variant="primary" icon="check" onClick={confirmClarify}>Clarify → todo</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

window.GTD = GTD;
