/* koopa.admin — Plan detail (entries, drag-reorder, audit gate) + stub */
const { useState: u2S } = React;

const PHASES = ["foundation", "core", "applied", "mastery"];

function PlanDetail({ go, toast }) {
  const p = K.plan;            // { plan, entries, progress, attempts }
  const pl = p.plan;           // plan fields are nested (de-embedded read-model)
  const [entries, setEntries] = u2S(p.entries);
  const [drag, setDrag] = u2S(null);
  const [over, setOver] = u2S(null);
  const [gate, setGate] = u2S(null); // entry being completed
  const [pickAttempt, setPickAttempt] = u2S(null);
  const [reason, setReason] = u2S("");
  const [skip, setSkip] = u2S(null); // entry being skipped
  const [skipReason, setSkipReason] = u2S("");

  // progress shape: { total, completed, skipped, substituted, remaining } — recomputed live as entries mutate
  const counts = entries.reduce((a, e) => { a[e.status] = (a[e.status] || 0) + 1; return a; }, {});
  const total = entries.length;
  const completed = counts.completed || 0;
  const substituted = counts.substituted || 0;
  const skipped = counts.skipped || 0;
  const remaining = total - completed - substituted - skipped;

  const onDrop = (i) => {
    if (drag === null || drag === i) { setDrag(null); setOver(null); return; }
    setEntries((xs) => { const c = [...xs]; const [m] = c.splice(drag, 1); c.splice(i, 0, m); return c; });
    setDrag(null); setOver(null); toast("Reordered entries", "route");
  };

  const openGate = (e) => { setGate(e); setPickAttempt(null); setReason(""); };
  const confirmGate = () => {
    if (!pickAttempt || !reason.trim()) return;
    setEntries((xs) => xs.map((e) => e.plan_entry_id === gate.plan_entry_id ? { ...e, status: "completed", completed_by_attempt_id: pickAttempt, reason: reason.trim() } : e));
    toast("Entry completed · justification logged", "check", "ok");
    setGate(null);
  };
  const openSkip = (e) => { setSkip(e); setSkipReason(""); };
  const confirmSkip = () => {
    if (!skipReason.trim()) return;
    setEntries((xs) => xs.map((e) => e.plan_entry_id === skip.plan_entry_id ? { ...e, status: "skipped", reason: skipReason.trim() } : e));
    toast("Entry skipped · reason logged", "defer");
    setSkip(null);
  };

  return (
    <div className="admin-body">
      <Topbar title="Learning plan" crumbs={["learning", "plans", pl.id]} actions={
        <><Btn icon="plus" onClick={() => toast("Added entry")}>Add entry</Btn><Btn icon="play" variant="primary" onClick={() => toast("Session started", "play")}>Start session</Btn></>
      } />
      <div className="detail-wrap">
        <div className="detail-top">
          <div style={{ flex: 1 }}>
            <h1 className="detail-title">{pl.title}</h1>
            <p className="detail-desc">{pl.description}</p>
          </div>
          <span className={"status-chip-lg st-in_progress"}><span className="dot" />{pl.status}</span>
        </div>
        <div className="detail-meta">
          <span className="meta-kv"><Icon name="globe" size={13} />domain <b>{pl.domain}</b></span>
          <span className="meta-kv"><Icon name="target" size={13} />goal <b>{pl.goal_name}</b></span>
          <span className="meta-kv"><Icon name="route" size={13} />entries <b>{total}</b></span>
        </div>

        <div className="plan-progress">
          <div className="pp-bar">
            <div className="pp-seg completed" style={{ width: (completed / total * 100) + "%" }} />
            <div className="pp-seg substituted" style={{ width: (substituted / total * 100) + "%" }} />
            <div className="pp-seg skipped" style={{ width: (skipped / total * 100) + "%" }} />
          </div>
          <div className="pp-legend">
            <span className="pp-leg"><span className="sw" style={{ background: "var(--success)" }} />{completed} completed</span>
            <span className="pp-leg"><span className="sw" style={{ background: "var(--brand)" }} />{substituted} substituted</span>
            <span className="pp-leg"><span className="sw" style={{ background: "var(--warn)", opacity: 0.6 }} />{skipped} skipped</span>
            <span className="pp-leg" style={{ color: "var(--fg-faint)" }}>{remaining} remaining</span>
          </div>
        </div>

        <div className="detail-grid">
          <div className="panel-card">
            <div className="panel-head"><span className="ic"><Icon name="route" size={15} /></span><h3>Plan entries</h3><span className="count">drag to reorder</span></div>
            {entries.map((e, i) => (
              <div key={e.plan_entry_id}
                className={"entry-row" + (e.status === "completed" ? " entry-done" : "") + (drag === i ? " dragging" : "") + (over === i ? " drop-target" : "")}
                draggable onDragStart={() => setDrag(i)} onDragEnter={() => setOver(i)}
                onDragOver={(ev) => ev.preventDefault()} onDrop={() => onDrop(i)} onDragEnd={() => { setDrag(null); setOver(null); }}>
                <span className="entry-grip"><Icon name="grip" size={15} /></span>
                <span className="entry-pos">{i + 1}</span>
                <span className="entry-title">{e.title}</span>
                <span className={"phase-badge phase-" + e.phase}>{e.phase}</span>
                <span className={"entry-state es-" + e.status}>{e.status}</span>
                {e.status !== "completed" ? (
                  <div style={{ display: "flex", gap: 6 }}>
                    {e.status !== "skipped" && <Btn size="sm" variant="ghost" icon="defer" onClick={() => openSkip(e)} title="Skip with reason">Skip</Btn>}
                    <Btn size="sm" icon="check" onClick={() => openGate(e)}>Complete</Btn>
                  </div>
                ) : (
                  <Btn size="sm" variant="ghost" icon="undo" onClick={() => { setEntries((xs) => xs.map((x) => x.plan_entry_id === e.plan_entry_id ? { ...x, status: "active", completed_by_attempt_id: undefined, reason: undefined } : x)); toast("Reopened entry", "undo"); }}>Reopen</Btn>
                )}
              </div>
            ))}
          </div>

          <div className="panel-card">
            <div className="panel-head"><span className="ic"><Icon name="sparkles" size={15} /></span><h3>Justifying attempts</h3><span className="count">{p.attempts.length}</span></div>
            <div style={{ padding: "4px 14px 12px" }}>
              {p.attempts.map((a) => (
                <div key={a.id} className="act-item" style={{ paddingLeft: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                    <span className={"k-chip " + (a.verdict === "passed" ? "" : "")} style={{ color: a.verdict === "passed" ? "var(--success)" : "var(--warn)", background: a.verdict === "passed" ? "var(--success-bg)" : "var(--warn-bg)" }}><span className="dot" />{a.verdict}</span>
                    <span className="act-when">{a.when}</span>
                  </div>
                  <div className="act-body">{a.title}</div>
                  <div className="obs-body" style={{ fontSize: 12, margin: "3px 0 0" }}>{a.note}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {gate && (
        <div className="scrim" onMouseDown={() => setGate(null)}>
          <div className="dialog" onMouseDown={(ev) => ev.stopPropagation()}>
            <div className="dialog-head">
              <span className="gate-req"><Icon name="alert" size={12} />audit gate · justification required</span>
              <h3 style={{ marginTop: 6 }}>Complete: {gate.title}</h3>
              <p>Marking an entry complete isn’t a silent toggle. Choose the attempt that justifies it and say why — this is written to the plan’s audit log.</p>
            </div>
            <div className="dialog-body">
              <div>
                <div className="field-label" style={{ marginBottom: 8 }}><span className="req">*</span> Justifying attempt</div>
                <div className="pick-list">
                  {K.plan.attempts.map((a) => (
                    <div key={a.id} className={"pick" + (pickAttempt === a.id ? " sel" : "")} onClick={() => setPickAttempt(a.id)}>
                      <span className="pick-radio" />
                      <div className="pick-main">
                        <div className="pick-title">{a.title}</div>
                        <div className="pick-meta">{a.verdict} · {a.when} · {a.note}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="field" style={{ margin: 0 }}>
                <span className="field-label"><span className="req">*</span> Why does this attempt justify completion?</span>
                <textarea className="field-area" placeholder="e.g. Demonstrated the replication tradeoff under partition without prompting — the entry’s intent is met." value={reason} onChange={(e) => setReason(e.target.value)} />
              </div>
            </div>
            <div className="dialog-foot">
              {(!pickAttempt || !reason.trim()) && <span className="field-msg err" style={{ minHeight: 0 }}><Icon name="alert" size={12} />Both are required</span>}
              <span className="spacer" />
              <Btn onClick={() => setGate(null)}>Cancel</Btn>
              <Btn variant="primary" icon="check" disabled={!pickAttempt || !reason.trim()} onClick={confirmGate}>Complete & log</Btn>
            </div>
          </div>
        </div>
      )}

      {skip && (
        <div className="scrim" onMouseDown={() => setSkip(null)}>
          <div className="dialog" onMouseDown={(ev) => ev.stopPropagation()}>
            <div className="dialog-head">
              <span className="gate-req"><Icon name="alert" size={12} />reason required</span>
              <h3 style={{ marginTop: 6 }}>Skip: {skip.title}</h3>
              <p>Skipping is a real decision, not a delete. Say why so the plan’s history stays honest — this is logged against the entry.</p>
            </div>
            <div className="dialog-body">
              <div className="field" style={{ margin: 0 }}>
                <span className="field-label"><span className="req">*</span> Why skip this entry?</span>
                <textarea className="field-area" placeholder="e.g. Covered the rate-limiter design ad hoc during the self-host work — re-attempting here adds no signal." value={skipReason} onChange={(e) => setSkipReason(e.target.value)} />
              </div>
            </div>
            <div className="dialog-foot">
              {!skipReason.trim() && <span className="field-msg err" style={{ minHeight: 0 }}><Icon name="alert" size={12} />A reason is required</span>}
              <span className="spacer" />
              <Btn onClick={() => setSkip(null)}>Cancel</Btn>
              <Btn variant="primary" icon="defer" disabled={!skipReason.trim()} onClick={confirmSkip}>Skip & log</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ============================================================ STUB (not-yet-built areas) */
const STUB_COPY = {
  plan: { t: "Plan", p: "The day-planner — pull todos into time slots, balance energy, defer with intent." },
  inbox: { t: "GTD Inbox", p: "Unclarified captures waiting to become todos. Fast keyboard triage: clarify, defer, drop." },
  todos: { t: "Todos", p: "Segmented views — Inbox, Today, Pending, Someday, Recurring, History — with a persistent capture bar." },
  projects: { t: "Projects", p: "PARA projects with progress, linked goals and open todos." },
  areas: { t: "Areas", p: "The standing areas of responsibility everything rolls up to." },
  content: { t: "Content", p: "The full content table across seven types — already live in the admin kit." },
  notes: { t: "Notes", p: "Atomic notes with a maturity rail: seed → stub → evergreen → archived." },
  feeds: { t: "Feeds", p: "RSS sources, crawl health, and the highlight queue that feeds Today." },
  tags: { t: "Tags & topics", p: "The topic graph that organises content by idea, not by date." },
  search: { t: "Search", p: "Semantic search across everything koopa knows — pgvector-backed." },
  learning: { t: "Learning dashboard", p: "Mastery, streak, observations and concept-weakness signals — with graceful per-widget loading." },
  sessions: { t: "Sessions", p: "Logged learning sessions with attempts and FSRS scheduling." },
  concepts: { t: "Concepts", p: "Every concept with its mastery stage and next review." },
  hypotheses: { t: "Hypotheses", p: "Open hypotheses about how you learn, tested against the observation log." },
  domains: { t: "Domains", p: "The domains plans, concepts and observations belong to." },
  health: { t: "System health", p: "Service status, queue depth and error budgets." },
  stats: { t: "Stats", p: "Counts and trends across the whole knowledge engine." },
  activity: { t: "Activity", p: "The unified event stream — every agent and human action." },
  agents: { t: "Agents", p: "Read-only view of the agents reading from and writing to koopa via MCP." },
};
function Stub({ route, go }) {
  const c = STUB_COPY[route] || { t: route, p: "Coming next in the build queue." };
  return (
    <div className="admin-body">
      <Topbar title={c.t} crumbs={[route]} />
      <div className="stub">
        <span className="hex"><Hexagon size={56} /></span>
        <h2>{c.t}</h2>
        <p>{c.p}</p>
        <span className="next-tag">next in the build queue</span>
        <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
          <Btn icon="sunrise" onClick={() => go("today")}>Back to Today</Btn>
        </div>
      </div>
    </div>
  );
}

window.PlanDetail = PlanDetail;
window.Stub = Stub;
