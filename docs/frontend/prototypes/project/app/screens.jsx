/* koopa.admin — screens: Today, Goals, Plans, stubs */
const { useState: uS, useEffect: uE, useRef: uR } = React;

/* ============================================================ TODAY */
function TodayScreen({ dataState, go, toast }) {
  const d = K.today;
  const [plan, setPlan] = uS(d.committed_todos);
  const [loose, setLoose] = uS({ overdue: d.overdue_todos, today: d.today_todos, upcoming: d.upcoming_todos });
  uE(() => { setPlan(K.today.committed_todos); setLoose({ overdue: K.today.overdue_todos, today: K.today.today_todos, upcoming: K.today.upcoming_todos }); }, [dataState]);
  const completed = plan.filter((i) => i.state === "done").length;
  const planned = d.plan_completion.planned;
  const deferred = d.plan_completion.deferred;
  const pct = Math.round((completed / planned) * 100);

  const advance = (id) => {
    setPlan((xs) => xs.map((i) => {
      if (i.id !== id) return i;
      const next = i.state === "todo" ? "in_progress" : "done";
      if (next === "done") toast("Marked done · " + (i.title.length > 30 ? i.title.slice(0, 30) + "…" : i.title), "check", "ok");
      return { ...i, state: next };
    }));
  };
  const completeLoose = (key, id) => { setLoose((s) => ({ ...s, [key]: s[key].filter((x) => x.id !== id) })); toast("Completed", "check", "ok"); };

  return (
    <div className="admin-body">
      <Topbar title="Today" crumbs={["daily", "today"]} onSearch={() => go("@cmdk")} actions={
        <>
          <Btn icon="calendar" onClick={() => go("plan")}>Plan</Btn>
          <Btn icon="play" variant="primary" onClick={() => toast("Session started · Replication & consistency", "play")}>Start session</Btn>
        </>
      } />
      <div className="today-wrap">
        <div className="day-header">
          <div>
            <h1 className="day-title">Good afternoon, Koopa</h1>
            <div className="day-date">{d.date}</div>
          </div>
          <div className="spacer" />
          <div className="capture-bar" onClick={() => go("@cmdk")}>
            <Icon name="plus" size={15} style={{ color: "var(--fg-subtle)" }} />
            <input placeholder="Capture a todo…" readOnly onFocus={() => go("@cmdk")} />
            <kbd className="kbd">⌘K</kbd>
          </div>
        </div>

        {dataState === "loading" && <TodayLoading />}
        {dataState === "error" && (
          <div className="panel-card"><div className="state-error">
            <span className="hex"><Hexagon size={46} /></span>
            <h4>Couldn’t load today’s plan</h4>
            <p>The daily-plan service didn’t respond. Your captures are safe in the inbox.</p>
            <Btn icon="refresh" onClick={() => toast("Retrying…", "refresh")}>Retry</Btn>
          </div></div>
        )}
        {dataState === "empty" && (
          <div className="panel-card"><div className="state-empty">
            <span className="hex"><Hexagon size={46} /></span>
            <h4>Nothing planned yet</h4>
            <p>Pull todos into today, or capture something new. An empty day is a blank page, not a failure.</p>
            <Btn icon="plus" variant="primary" onClick={() => go("@cmdk")}>Capture a todo</Btn>
          </div></div>
        )}

        {dataState === "populated" && (
          <>
            <div className="day-progress">
              <div className="dp-figs">
                <div className="dp-fig"><span className="n">{planned}</span><span className="l">Planned</span></div>
                <div className="dp-fig"><span className="n done">{completed}</span><span className="l">Completed</span></div>
                <div className="dp-fig"><span className="n deferred">{deferred}</span><span className="l">Deferred</span></div>
              </div>
              <div className="dp-bar">
                <div className="dp-seg done" style={{ width: (completed / planned * 100) + "%" }} />
                <div className="dp-seg deferred" style={{ width: (deferred / planned * 100) + "%" }} />
              </div>
              <div className="dp-pct">{pct}%</div>
            </div>

            <div className="today-grid">
              <div className="today-col">
                <div className="panel-card">
                  <div className="panel-head">
                    <span className="ic"><Icon name="calendar" size={15} /></span>
                    <h3>Today’s plan</h3><span className="count">{completed}/{planned}</span>
                    <span className="spacer" />
                    <Btn icon="plus" variant="ghost" size="sm" onClick={() => go("@cmdk")}>Add</Btn>
                  </div>
                  {plan.map((i) => (
                    <div key={i.id} className={"row" + (i.state === "done" ? " is-done" : "")}>
                      <span className="pos-num">{i.position}</span>
                      <div className={"check" + (i.state === "done" ? " done" : "")} onClick={() => advance(i.id)}>
                        {i.state === "done" && <Icon name="check" size={11} stroke={2.5} />}
                        {i.state === "in_progress" && <span className="ip-dot" />}
                      </div>
                      <span className="r-title">{i.title}</span>
                      <div className="r-meta">
                        {i.state === "in_progress" && <span className="tstate in_progress">in progress</span>}
                        {i.project_id && <span className="k-chip"><span className="dot" style={{ background: "var(--brand)" }} />{i.project_id}</span>}
                        <EnergyMeter level={i.energy} />
                        <Btn className="advance" icon="arrowRight" variant="ghost" size="sm" onClick={() => advance(i.id)} title="Advance" />
                      </div>
                    </div>
                  ))}
                </div>

                <div className="panel-card">
                  <div className="panel-head">
                    <span className="ic"><Icon name="listChecks" size={15} /></span>
                    <h3>Loose todos</h3>
                    <span className="count">{loose.overdue.length + loose.today.length + loose.upcoming.length}</span>
                    <span className="spacer" />
                    <Btn variant="ghost" size="sm" onClick={() => go("todos")}>Open Todos</Btn>
                  </div>
                  {[["overdue", "Overdue"], ["today", "Due today"], ["upcoming", "Upcoming"]].map(([k, label]) => (
                    loose[k].length > 0 ? (
                      <div key={k}>
                        <div className="gtd-group" style={{ padding: "8px 14px 4px" }}>{label} <span>{loose[k].length}</span></div>
                        {loose[k].map((t) => (
                          <div key={t.id} className="row">
                            <div className="check" title="complete" onClick={() => completeLoose(k, t.id)} />
                            <span className="r-title">{t.title}</span>
                            <div className="r-meta">
                              {t.due && <span className={"due-chip " + (String(t.due).includes("overdue") ? "overdue" : t.due === "today" ? "soon" : "")}>{t.due}</span>}
                              {t.project && <span className="k-chip"><span className="dot" style={{ background: "var(--brand)" }} />{t.project}</span>}
                              <EnergyMeter level={t.energy} />
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : null
                  ))}
                </div>
              </div>

              <div className="today-col">
                {d.active_session && (
                  <div className="session-card">
                    <div className="session-head">
                      <span className="session-live"><span className="pulse" />Active session</span>
                    </div>
                    <div className="session-body">
                      <div className="session-concept">{d.active_session.title}</div>
                      <div className="session-sub">{d.active_session.domain} · {d.active_session.plan} · attempt {d.active_session.attempts}</div>
                      <div className="session-timer">{d.active_session.elapsed}</div>
                      <div className="session-foot">
                        <Btn icon="play" variant="primary" size="sm" onClick={() => toast("Resumed session", "play")}>Resume</Btn>
                        <Btn icon="check" size="sm" onClick={() => toast("Session logged · 42m", "check", "ok")}>Log & end</Btn>
                      </div>
                    </div>
                  </div>
                )}

                <div className="panel-card">
                  <div className="panel-head"><span className="ic"><Icon name="target" size={15} /></span><h3>Active goals</h3><span className="count">{d.active_goals.length}</span></div>
                  {d.active_goals.map((g) => (
                    <div key={g.id} className="goal-row" onClick={() => go("goal")}>
                      <div className="goal-row-main">
                        <span className="goal-row-title">{g.title}</span>
                        <div className="goal-row-meta">
                          <span className={"status-chip-lg st-" + g.status} style={{ fontSize: 9, padding: "0 6px" }}><span className="dot" />{g.status.replace("_", " ")}</span>
                          <span className="cell-date">{g.milestones} · {g.area}</span>
                        </div>
                      </div>
                      <div className="proj-bar" style={{ width: 56, flexShrink: 0 }}><i style={{ width: (g.progress * 100) + "%" }} /></div>
                    </div>
                  ))}
                </div>

                <div className="panel-card">
                  <div className="panel-head"><span className="ic"><Icon name="flask" size={15} /></span><h3>Unverified hypotheses</h3><span className="count">{d.unverified_hypotheses.length}</span></div>
                  {d.unverified_hypotheses.map((h) => (
                    <div key={h.id} className="hyp-row">
                      <p className="hyp-claim">“{h.claim}”</p>
                      <div className="hyp-inval"><span className="micro-lbl">invalidates if</span> {h.invalidation_condition}</div>
                      <div className="hyp-meta"><span className="tstate someday">unverified</span> {h.created_by} · observed {h.observed_date}</div>
                    </div>
                  ))}
                </div>

                <div className="panel-card">
                  <div className="panel-head">
                    <span className="ic"><Icon name="rss" size={15} /></span>
                    <h3>RSS highlights</h3><span className="count">{d.rss_highlights.length}</span>
                    <span className="spacer" />
                    <Btn variant="ghost" size="sm" onClick={() => go("feeds")}>All feeds</Btn>
                  </div>
                  {d.rss_highlights.map((r, idx) => (
                    <div key={idx} className="rss-row">
                      <span className="rss-dot" style={{ background: r.color }} />
                      <div className="rss-main">
                        <div className="rss-title">{r.title}</div>
                        <div className="rss-src">{r.feed_name} · {r.created_at}</div>
                      </div>
                      <Btn className="save" icon="bookmark" variant="ghost" size="sm" title="Save" onClick={() => toast("Saved to bookmarks", "bookmark")} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
function TodayLoading() {
  return (
    <>
      <div className="day-progress"><div className="skel skel-line" style={{ width: 220, height: 22 }} /><div className="dp-bar skel" style={{ flex: 1 }} /><div className="skel" style={{ width: 48, height: 22 }} /></div>
      <div className="today-grid">
        <div className="panel-card">
          <div className="panel-head"><div className="skel skel-line" style={{ width: 90 }} /></div>
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <div className="skel-row" key={i}><div className="skel" style={{ width: 34, height: 9 }} /><div className="skel" style={{ width: 15, height: 15, borderRadius: 2 }} /><div className="skel skel-line" style={{ flex: 1, maxWidth: 200 + (i % 3) * 60 }} /></div>
          ))}
        </div>
        <div className="today-col">
          <div className="panel-card" style={{ height: 150 }}><div className="panel-head"><div className="skel skel-line" style={{ width: 110 }} /></div><div style={{ padding: 14 }}><div className="skel skel-line" style={{ width: "70%", height: 14, marginBottom: 12 }} /><div className="skel" style={{ width: 120, height: 28 }} /></div></div>
          <div className="panel-card"><div className="panel-head"><div className="skel skel-line" style={{ width: 80 }} /></div>{[0, 1, 2].map((i) => <div className="skel-row" key={i}><div className="skel skel-line" style={{ flex: 1 }} /></div>)}</div>
        </div>
      </div>
    </>
  );
}

/* ============================================================ GOALS LIST */
function GoalsList({ go }) {
  return (
    <div className="admin-body">
      <Topbar title="Goals" crumbs={["commitment", "goals"]} actions={
        <Btn icon="plus" variant="primary" onClick={() => go("goal-new")}>New goal</Btn>
      } />
      <div className="content-toolbar">
        <div className="content-chips">
          {["all", "not_started", "in_progress", "on_hold", "done", "abandoned"].map((s, i) => (
            <button key={s} className={"filter-chip" + (i === 0 ? " active" : "")}>{s}</button>
          ))}
        </div>
        <div style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-subtle)" }}>{K.goalsList.length} goals</div>
      </div>
      <table className="content-table">
        <thead><tr><th>Title</th><th>Area</th><th>Quarter</th><th>Milestones</th><th>Status</th><th>ID</th></tr></thead>
        <tbody>
          {K.goalsList.map((g) => (
            <tr key={g.id}>
              <td className="cell-title" onClick={() => go("goal")}>{g.title}</td>
              <td><span className="k-chip">{g.area}</span></td>
              <td><span className="cell-date">{g.quarter}</span></td>
              <td><span className="cell-date">{g.done}/{g.milestones}</span></td>
              <td><span className={"status-chip-lg st-" + g.status} style={{ fontSize: 10, padding: "1px 8px" }}><span className="dot" />{g.status.replace("_", " ")}</span></td>
              <td><span className="cell-id">{g.id}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ============================================================ GOAL CREATE (Signal Forms) */
function GoalNew({ go, toast }) {
  const [f, setF] = uS({ title: "", description: "", area: "", quarter: "", deadline: "" });
  const [touched, setTouched] = uS({});
  const [submitted, setSubmitted] = uS(false);
  const set = (k, v) => setF((s) => ({ ...s, [k]: v }));
  const blur = (k) => setTouched((s) => ({ ...s, [k]: true }));
  const errors = {
    title: !f.title.trim() ? "Title is required." : f.title.trim().length < 6 ? "Give it at least 6 characters — a real commitment." : null,
    area: !f.area ? "Pick an area (PARA)." : null,
    quarter: !f.quarter ? "Pick a target quarter." : null,
  };
  const showErr = (k) => (touched[k] || submitted) && errors[k];
  const valid = !errors.title && !errors.area && !errors.quarter;

  const submit = () => {
    setSubmitted(true);
    if (!valid) { toast("Fix the highlighted fields", "alert"); return; }
    toast("Goal created · status set to not_started", "check", "ok");
    go("goal");
  };
  return (
    <div className="admin-body">
      <Topbar title="New goal" crumbs={["commitment", "goals", "new"]} actions={
        <><Btn onClick={() => go("goals")}>Cancel</Btn><Btn icon="check" variant="primary" disabled={submitted && !valid} onClick={submit}>Create goal</Btn></>
      } />
      <div className="form-canvas">
        <div className="form-card">
          <h1 className="form-title">New goal</h1>
          <p className="form-sub">A goal is a destination, not a task. Status is set by the system to <span className="k-mono" style={{ color: "var(--fg-muted)" }}>not_started</span> on create — you change it from the goal page once work begins.</p>
          {submitted && !valid && <div className="form-banner err"><Icon name="alert" size={15} />Some fields need attention before this can be created.</div>}

          <div className={"field" + (showErr("title") ? " invalid" : f.title && !errors.title ? " valid" : "")}>
            <span className="field-label"><span className="req">*</span> Title</span>
            <input className="field-input" placeholder="Ship koopa v1 to a stable, self-hostable release"
              value={f.title} onChange={(e) => set("title", e.target.value)} onBlur={() => blur("title")} maxLength={90} />
            <div className={"field-msg " + (showErr("title") ? "err" : "hint")}>
              {showErr("title") ? <><Icon name="alert" size={12} />{errors.title}</> : "Declarative and specific. You’ll read this every quarter."}
              <span className="field-count">{f.title.length}/90</span>
            </div>
          </div>

          <div className="field">
            <span className="field-label">Description <span className="opt">— optional</span></span>
            <textarea className="field-area" placeholder="Why this goal, and what “done” actually looks like. The reasoning behind it matters more than the headline."
              value={f.description} onChange={(e) => set("description", e.target.value)} />
            <div className="field-msg hint">Context for future-you and the agents that read this.</div>
          </div>

          <div className="field-row">
            <div className={"field" + (showErr("area") ? " invalid" : "")}>
              <span className="field-label"><span className="req">*</span> Area (PARA)</span>
              <select className="field-select" value={f.area} onChange={(e) => { set("area", e.target.value); blur("area"); }} onBlur={() => blur("area")}>
                <option value="">Select an area…</option>
                {K.areas.map((a) => <option key={a} value={a}>{a}</option>)}
              </select>
              <div className={"field-msg " + (showErr("area") ? "err" : "hint")}>{showErr("area") ? <><Icon name="alert" size={12} />{errors.area}</> : "Where this lives."}</div>
            </div>
            <div className={"field" + (showErr("quarter") ? " invalid" : "")}>
              <span className="field-label"><span className="req">*</span> Quarter</span>
              <select className="field-select" value={f.quarter} onChange={(e) => { set("quarter", e.target.value); blur("quarter"); }} onBlur={() => blur("quarter")}>
                <option value="">Select a quarter…</option>
                {K.quarters.map((qq) => <option key={qq} value={qq}>{qq}</option>)}
              </select>
              <div className={"field-msg " + (showErr("quarter") ? "err" : "hint")}>{showErr("quarter") ? <><Icon name="alert" size={12} />{errors.quarter}</> : "Target horizon."}</div>
            </div>
          </div>

          <div className="field" style={{ maxWidth: 240 }}>
            <span className="field-label">Deadline <span className="opt">— optional</span></span>
            <input className="field-input" type="date" value={f.deadline} onChange={(e) => set("deadline", e.target.value)} />
            <div className="field-msg hint">A soft commitment, movable with a reason.</div>
          </div>

          <div className="form-actions">
            <span className="k-chip"><Icon name="flag" size={12} />status set on create: <b className="k-mono" style={{ color: "var(--fg-muted)" }}>not_started</b></span>
            <span className="spacer" />
            <Btn onClick={() => go("goals")}>Cancel</Btn>
            <Btn icon="check" variant="primary" disabled={submitted && !valid} onClick={submit}>Create goal</Btn>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================================================ GOAL DETAIL */
const GOAL_STATES = [
  { id: "not_started", label: "not started" },
  { id: "in_progress", label: "in progress" },
  { id: "on_hold", label: "on hold" },
  { id: "done", label: "done" },
  { id: "abandoned", label: "abandoned" },
];
function GoalDetail({ go, toast }) {
  const g = K.goal;
  const [status, setStatus] = uS(g.status);
  const [menuOpen, setMenuOpen] = uS(false);
  const [ms, setMs] = uS(g.milestones);
  const [newMs, setNewMs] = uS("");
  const stColor = { not_started: "var(--fg-subtle)", in_progress: "var(--info)", on_hold: "var(--warn)", done: "var(--success)", abandoned: "var(--fg-faint)" };
  const addMs = () => { if (!newMs.trim()) return; setMs((xs) => [...xs, { id: "m" + Date.now(), title: newMs.trim(), done: false }]); setNewMs(""); toast("Milestone added", "plus"); };
  const toggleMs = (id) => setMs((xs) => xs.map((m) => m.id === id ? { ...m, done: !m.done } : m));
  const msDone = ms.filter((m) => m.done).length;

  return (
    <div className="admin-body" onClick={() => menuOpen && setMenuOpen(false)}>
      <Topbar title="Goal" crumbs={["commitment", "goals", g.id]} actions={
        <><Btn icon="plus" onClick={() => toast("Linked a project")}>Link project</Btn><Btn icon="external">Open public</Btn></>
      } />
      <div className="detail-wrap">
        <div className="detail-top">
          <div style={{ flex: 1 }}>
            <h1 className="detail-title">{g.title}</h1>
            <p className="detail-desc">{g.description}</p>
          </div>
          <div className="status-control" onClick={(e) => e.stopPropagation()}>
            <div className={"status-chip-lg st-" + status} onClick={() => setMenuOpen((o) => !o)}>
              <span className="dot" />{GOAL_STATES.find((s) => s.id === status).label}
              <Icon name="chevronDown" size={13} />
            </div>
            {menuOpen && (
              <div className="status-menu">
                {GOAL_STATES.map((s) => (
                  <button key={s.id} onClick={() => { setStatus(s.id); setMenuOpen(false); toast("Status → " + s.label, "flag"); }}>
                    <span className="dot" style={{ background: stColor[s.id] }} />{s.label}
                    {s.id === status && <Icon name="check" size={13} style={{ marginLeft: "auto", color: "var(--brand)" }} />}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="detail-meta">
          <span className="meta-kv"><Icon name="layers" size={13} />area <b>{g.area}</b></span>
          <span className="meta-kv"><Icon name="calendar" size={13} />quarter <b>{g.quarter}</b></span>
          <span className="meta-kv"><Icon name="flag" size={13} />deadline <b>{g.deadline}</b></span>
          <span className="meta-kv"><Icon name="check" size={13} />milestones <b>{msDone}/{ms.length}</b></span>
        </div>

        <div className="detail-grid">
          <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
            <div className="panel-card">
              <div className="panel-head"><span className="ic"><Icon name="check" size={15} /></span><h3>Milestones</h3><span className="count">{msDone}/{ms.length}</span></div>
              {ms.map((m) => (
                <div key={m.id} className={"ms-row" + (m.done ? " done" : "")}>
                  <div className={"ms-check" + (m.done ? " done" : "")} onClick={() => toggleMs(m.id)}>{m.done && <Icon name="check" size={11} stroke={2.5} />}</div>
                  <span className="ms-title">{m.title}</span>
                </div>
              ))}
              <div className="ms-add">
                <Icon name="plus" size={15} style={{ color: "var(--fg-subtle)" }} />
                <input placeholder="Add a milestone…" value={newMs} onChange={(e) => setNewMs(e.target.value)} onKeyDown={(e) => e.key === "Enter" && addMs()} />
                <Btn variant="primary" size="sm" disabled={!newMs.trim()} onClick={addMs}>Add</Btn>
              </div>
            </div>

            <div className="panel-card">
              <div className="panel-head"><span className="ic"><Icon name="folder" size={15} /></span><h3>Linked projects</h3><span className="count">{g.projects.length}</span></div>
              {g.projects.map((p) => (
                <div key={p.id} className="proj-row">
                  <Icon name="folder" size={15} style={{ color: "var(--fg-subtle)" }} />
                  <span className="proj-name">{p.name}</span>
                  <span className="k-chip">{p.open} open</span>
                  <div className="proj-bar"><i style={{ width: (p.progress * 100) + "%" }} /></div>
                  <span className="cell-date">{Math.round(p.progress * 100)}%</span>
                </div>
              ))}
            </div>
          </div>

          <div className="panel-card">
            <div className="panel-head"><span className="ic"><Icon name="activity" size={15} /></span><h3>Recent activity</h3></div>
            <div style={{ padding: "6px 16px 14px" }} className="act-rail">
              {g.recent_activity.map((a) => (
                <div key={a.id} className="act-item">
                  <span className={"act-node" + (a.brand ? " brand" : "")} />
                  <div className="act-body" dangerouslySetInnerHTML={{ __html: a.body }} />
                  <div className="act-when">{a.when}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================================================ PLAN CREATE */
function PlanNew({ go, toast }) {
  const [f, setF] = uS({ title: "", description: "", domain: "", goal: "", target: 9 });
  const [touched, setTouched] = uS({});
  const [submitted, setSubmitted] = uS(false);
  const set = (k, v) => setF((s) => ({ ...s, [k]: v }));
  const blur = (k) => setTouched((s) => ({ ...s, [k]: true }));
  const errors = { title: !f.title.trim() ? "Title is required." : null, domain: !f.domain ? "A plan must belong to a domain." : null };
  const showErr = (k) => (touched[k] || submitted) && errors[k];
  const valid = !errors.title && !errors.domain;
  const submit = () => { setSubmitted(true); if (!valid) { toast("Fix the highlighted fields", "alert"); return; } toast("Learning plan created · status draft", "check", "ok"); go("plan-detail"); };

  return (
    <div className="admin-body">
      <Topbar title="New learning plan" crumbs={["learning", "plans", "new"]} actions={
        <><Btn onClick={() => go("plans")}>Cancel</Btn><Btn icon="check" variant="primary" disabled={submitted && !valid} onClick={submit}>Create plan</Btn></>
      } />
      <div className="form-canvas">
        <div className="form-card">
          <h1 className="form-title">New learning plan</h1>
          <p className="form-sub">A plan is an ordered path through a domain. Entries, phases and the audit log come after — start with intent.</p>

          <div className={"field" + (showErr("title") ? " invalid" : f.title && !errors.title ? " valid" : "")}>
            <span className="field-label"><span className="req">*</span> Title</span>
            <input className="field-input" placeholder="System design fluency — from patterns to tradeoffs"
              value={f.title} onChange={(e) => set("title", e.target.value)} onBlur={() => blur("title")} maxLength={80} />
            <div className={"field-msg " + (showErr("title") ? "err" : "hint")}>{showErr("title") ? <><Icon name="alert" size={12} />{errors.title}</> : "What fluency are you building?"}<span className="field-count">{f.title.length}/80</span></div>
          </div>

          <div className="field">
            <span className="field-label">Description <span className="opt">— optional</span></span>
            <textarea className="field-area" placeholder="The shape of the path and how you’ll know it worked." value={f.description} onChange={(e) => set("description", e.target.value)} />
            <div className="field-msg hint">&nbsp;</div>
          </div>

          <div className="field-row">
            <div className={"field" + (showErr("domain") ? " invalid" : "")}>
              <span className="field-label"><span className="req">*</span> Domain</span>
              <select className="field-select" value={f.domain} onChange={(e) => { set("domain", e.target.value); blur("domain"); }} onBlur={() => blur("domain")}>
                <option value="">Select a domain…</option>
                {K.domains.map((dm) => <option key={dm} value={dm}>{dm}</option>)}
              </select>
              <div className={"field-msg " + (showErr("domain") ? "err" : "hint")}>{showErr("domain") ? <><Icon name="alert" size={12} />{errors.domain}</> : "Concepts & observations roll up here."}</div>
            </div>
            <div className="field">
              <span className="field-label">Goal <span className="opt">— optional</span></span>
              <select className="field-select" value={f.goal} onChange={(e) => set("goal", e.target.value)}>
                <option value="">Not linked</option>
                {K.goalsList.map((gg) => <option key={gg.id} value={gg.id}>{gg.title.length > 40 ? gg.title.slice(0, 40) + "…" : gg.title}</option>)}
              </select>
              <div className="field-msg hint">Tie this plan to a commitment.</div>
            </div>
          </div>

          <div className="field">
            <span className="field-label">Target entry count</span>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <input type="range" min="3" max="20" value={f.target} onChange={(e) => set("target", +e.target.value)} style={{ width: 260, accentColor: "var(--brand)" }} />
              <span className="k-mono" style={{ fontFamily: "var(--font-display)", fontSize: 20, fontWeight: 600, color: "var(--fg)", width: 30 }}>{f.target}</span>
              <span className="field-msg hint" style={{ minHeight: 0 }}>entries to scaffold</span>
            </div>
          </div>

          <div className="form-actions">
            <span className="k-chip"><Icon name="flag" size={12} />status on create: <b className="k-mono" style={{ color: "var(--fg-muted)" }}>draft</b></span>
            <span className="spacer" />
            <Btn onClick={() => go("plans")}>Cancel</Btn>
            <Btn icon="check" variant="primary" disabled={submitted && !valid} onClick={submit}>Create plan</Btn>
          </div>
        </div>
      </div>
    </div>
  );
}

window.TodayScreen = TodayScreen;
window.GoalsList = GoalsList;
window.GoalNew = GoalNew;
window.GoalDetail = GoalDetail;
window.PlanNew = PlanNew;
