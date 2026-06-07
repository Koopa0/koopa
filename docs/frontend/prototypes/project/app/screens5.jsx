/* koopa.admin — Learning Dashboard (screen 6), graceful per-widget loading */
const { useState: e5S, useEffect: e5E } = React;

/* Each widget loads independently; one failing never takes the page down. */
function Widget({ title, icon, meta, delay = 400, outcome = "ok", emptyCopy, children }) {
  const [st, setSt] = e5S("loading");
  e5E(() => { const t = setTimeout(() => setSt(outcome), delay); return () => clearTimeout(t); }, []);
  const retry = () => { setSt("loading"); setTimeout(() => setSt("ok"), 650); };
  return (
    <div className="learning-card widget">
      <div className="card-head">
        <h3><Icon name={icon} size={15} style={{ verticalAlign: "-2px", marginRight: 7 }} />{title}</h3>
        {meta != null && st === "ok" && <span className="meta">{meta}</span>}
        {st === "loading" && <span className="meta" style={{ color: "var(--fg-faint)" }}>loading…</span>}
      </div>
      {st === "loading" && <div className="widget-skel">{[0, 1, 2].map((i) => <div key={i} className="skel skel-line" style={{ height: 10, marginBottom: 12, width: ["90%", "75%", "60%"][i] }} />)}</div>}
      {st === "error" && (
        <div className="state-error" style={{ padding: "22px 16px" }}>
          <span className="hex"><Hexagon size={34} /></span>
          <h4>Couldn’t load this widget</h4>
          <p>The reader returned a warning. The rest of the dashboard is unaffected.</p>
          <Btn icon="refresh" size="sm" onClick={retry}>Retry</Btn>
        </div>
      )}
      {st === "empty" && (
        <div className="state-empty" style={{ padding: "22px 16px" }}>
          <span className="hex"><Hexagon size={34} /></span>
          <h4>{emptyCopy ? emptyCopy[0] : "Nothing here yet"}</h4>
          <p>{emptyCopy ? emptyCopy[1] : "Come back once there’s signal."}</p>
        </div>
      )}
      {st === "ok" && children}
    </div>
  );
}

const SIGNAL_COLOR = { weakness: "var(--error)", mastery: "var(--success)", improvement: "var(--brand)" };

function LearningDashboard({ go, toast }) {
  const L = K.learning;
  return (
    <div className="admin-body">
      <Topbar title="Learning dashboard" crumbs={["learning", "dashboard"]} onSearch={() => go("@cmdk")} actions={
        <><Btn icon="compass" onClick={() => go("concepts")}>Concepts</Btn><Btn icon="play" variant="primary" onClick={() => toast("Session started", "play")}>Start session</Btn></>
      } />
      <div className="dash-grid">
        {/* Mastery overview — full width */}
        <div className="dash-wide">
          <Widget title="Mastery overview" icon="brain" meta={L.total_concepts + " concepts"} delay={300}>
            <div className="stage-pills">
              {L.mastery_stages.map((s, i) => (
                <div key={s.id} className={"stage-pill" + (i === 2 ? " active" : "")}>
                  <div className="n">{s.n}</div>
                  <div className="lbl">{s.id}</div>
                </div>
              ))}
            </div>
            <div className="mastery-foot">
              <div className="mastery-avg">
                <span className="micro">avg mastery</span>
                <div className="avg-bar"><i style={{ width: (L.avg_mastery * 100) + "%" }} /></div>
                <span className="avg-n">{Math.round(L.avg_mastery * 100)}%</span>
              </div>
              <span className="caption">encounter → integrate, FSRS-scheduled</span>
            </div>
          </Widget>
        </div>

        <div className="dash-col">
          <Widget title="Concepts" icon="compass" meta="by mastery" delay={550}>
            {L.concepts.map((c) => (
              <div key={c.name} className="concept-row">
                <span className="concept-name">{c.name}<span className="concept-kind"> · {c.kind} · {c.domain}</span></span>
                <span className={"concept-stage " + c.stage}>{c.stage}</span>
                <div className="concept-bar"><div className="concept-bar-fill" style={{ width: (c.mastery * 100) + "%" }} /></div>
                <span className="concept-date">{c.next}</span>
              </div>
            ))}
          </Widget>

          <Widget title="Recent observations" icon="sparkles" meta={L.observations.length} delay={800}>
            {L.observations.map((o, i) => (
              <div key={i} className="obs-row">
                <span className="obs-type" style={{ color: SIGNAL_COLOR[o.signal] }}>{o.signal} · {o.category}</span>
                <p className="obs-body">{o.body}</p>
                <div className="obs-meta">{o.domain} · {o.concept} · {o.when}</div>
              </div>
            ))}
          </Widget>
        </div>

        <div className="dash-col">
          {/* Streak deliberately demonstrates graceful per-widget failure — Retry recovers it */}
          <Widget title="Streak" icon="activity" delay={420} outcome="error">
            <div className="streak-figs">
              <div className="streak-fig"><span className="n">{L.streak.current}</span><span className="l">day streak</span></div>
              <div className="streak-fig"><span className="n">{L.streak.this_week}</span><span className="l">this week</span></div>
              <div className="streak-fig"><span className="n">{L.streak.best}</span><span className="l">best</span></div>
            </div>
            <div className="streak-grid">
              {Array.from({ length: 35 }).map((_, i) => {
                const v = (i * 7 + 3) % 5; // deterministic faux-heatmap
                return <span key={i} className="streak-cell" style={{ background: v === 0 ? "var(--bg)" : "color-mix(in oklch, var(--brand) " + (v * 22) + "%, var(--bg))" }} />;
              })}
            </div>
          </Widget>

          <Widget title="Concept weakness signals" icon="alert" meta={L.weaknesses.length} delay={950}>
            {L.weaknesses.map((w) => (
              <div key={w.name} className="weak-row">
                <div className="weak-main">
                  <span className="weak-name">{w.name}<span className="concept-kind"> · {w.domain}</span></span>
                  <span className="weak-signal">{w.signal}</span>
                </div>
                <span className="weak-mastery">{Math.round(w.mastery * 100)}%</span>
              </div>
            ))}
          </Widget>
        </div>
      </div>
    </div>
  );
}

window.LearningDashboard = LearningDashboard;
