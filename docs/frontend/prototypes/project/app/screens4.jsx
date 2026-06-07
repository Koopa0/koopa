/* koopa.admin — Content & Note editors (screen 5), bound to the real enums */
const { useState: e4S, useEffect: e4E, useRef: e4R } = React;

const CONTENT_TYPES = ["article", "essay", "build-log", "til", "digest"];
const CONTENT_STAGES = ["draft", "review", "published", "archived"];
const NOTE_KINDS = ["solve-note", "concept-note", "debug-postmortem", "decision-log", "reading-note", "musing"];
const MATURITIES = ["seed", "stub", "evergreen", "needs_revision", "archived"];
const TOPICS = ["go", "ai", "system-design", "leetcode", "reading"];

/* ---------- shared primitives ---------- */
function Toggle({ on, onClick, labelOn = "public", labelOff = "private" }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
      <button className={"toggle" + (on ? " on" : "")} onClick={onClick} role="switch" aria-checked={on}><span className="knob" /></button>
      <span className="ui-sm" style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: on ? "var(--brand)" : "var(--fg-subtle)" }}>{on ? labelOn : labelOff}</span>
    </div>
  );
}

function TagInput({ tags, onAdd, onRemove }) {
  const [v, setV] = e4S("");
  return (
    <div className="tag-input">
      {tags.map((t) => <span key={t} className="tag-token">{t} <span className="tag-x" onClick={() => onRemove(t)}>×</span></span>)}
      <input value={v} onChange={(e) => setV(e.target.value)} placeholder={tags.length ? "" : "add a tag…"}
        onKeyDown={(e) => { if (e.key === "Enter" && v.trim()) { onAdd(v.trim()); setV(""); } if (e.key === "Backspace" && !v && tags.length) onRemove(tags[tags.length - 1]); }}
        style={{ flex: 1, minWidth: 60, background: "transparent", border: "none", outline: "none", font: "inherit", fontSize: 11, color: "var(--fg)", fontFamily: "var(--font-mono)" }} />
    </div>
  );
}

function useAutosave(deps) {
  const [state, setState] = e4S("saved");
  const first = e4R(true);
  e4E(() => {
    if (first.current) { first.current = false; return; }
    setState("saving");
    const t = setTimeout(() => setState("saved"), 850);
    return () => clearTimeout(t);
  }, deps);
  return state;
}

function AutosaveDot({ state }) {
  return (
    <span className="autosave">
      <span className={"as-dot " + state} />
      {state === "saving" ? "Saving…" : "Saved · all changes stored"}
    </span>
  );
}

/* ---------- Content list ---------- */
function ContentList({ go }) {
  const [tf, setTf] = e4S("all");
  const [sf, setSf] = e4S("all");
  const rows = K.content.filter((c) => (tf === "all" || c.type === tf) && (sf === "all" || c.status === sf));
  return (
    <div className="admin-body">
      <Topbar title="Content" crumbs={["knowledge", "content"]} actions={<><Btn icon="plus">Import</Btn><Btn icon="plus" variant="primary" onClick={() => go("content-editor:" + K.content[0].id)}>New</Btn></>} />
      <div className="content-toolbar">
        <div className="content-chips">
          {["all", ...CONTENT_TYPES].map((t) => <button key={t} className={"filter-chip" + (tf === t ? " active" : "")} onClick={() => setTf(t)}>{t}</button>)}
        </div>
        <div className="filter-divider" />
        <div className="content-chips">
          {["all", ...CONTENT_STAGES].map((s) => <button key={s} className={"filter-chip" + (sf === s ? " active" : "")} onClick={() => setSf(s)}>{s}</button>)}
        </div>
        <div style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-subtle)" }}>{rows.length} of {K.content.length}</div>
      </div>
      <table className="content-table">
        <thead><tr><th>Title</th><th>Type</th><th>Topic</th><th>Actor</th><th>Quality</th><th>Status</th><th>Public</th><th>Updated</th></tr></thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id}>
              <td className="cell-title" onClick={() => go("content-editor:" + c.id)}>{c.title}</td>
              <td><span className="cell-type">{c.type}</span></td>
              <td><span className="cell-topic">{c.topic}</span></td>
              <td><span className="cell-type">{c.actor}</span></td>
              <td><span className="cell-date">{c.quality_score != null ? c.quality_score.toFixed(1) : "—"}</span></td>
              <td><StatusBadge status={c.status} /></td>
              <td><span className="cell-date">{c.is_public ? "yes" : "—"}</span></td>
              <td><span className="cell-date">{c.updated}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------- Content editor ---------- */
function ContentEditor({ id, go, toast }) {
  const item = K.content.find((c) => c.id === id) || K.content[0];
  const [title, setTitle] = e4S(item.title);
  const [body, setBody] = e4S(K.contentBody);
  const [type, setType] = e4S(item.type);
  const [topic, setTopic] = e4S(item.topic);
  const [tags, setTags] = e4S(item.tags);
  const [status, setStatus] = e4S(item.status);
  const [isPublic, setIsPublic] = e4S(item.is_public);
  const save = useAutosave([title, body, type, topic, tags]);
  const stageIdx = CONTENT_STAGES.indexOf(status);
  const [preview, setPreview] = e4S(false);
  const previewSlug = item.preview_slug || item.slug;

  const transition = (to, verb) => { setStatus(to); if (to === "published") setIsPublic(true); toast(verb, "flag"); };
  const actions = {
    draft: <Btn variant="primary" icon="arrowRight" onClick={() => transition("review", "Submitted for review")}>Submit for review</Btn>,
    review: <><Btn icon="undo" onClick={() => transition("draft", "Reverted to draft")}>Revert</Btn><Btn variant="primary" icon="check" onClick={() => transition("published", "Published")}>Publish</Btn></>,
    published: <Btn icon="bookmark" onClick={() => transition("archived", "Archived")}>Archive</Btn>,
    archived: <Btn icon="undo" onClick={() => transition("draft", "Reverted to draft")}>Revert to draft</Btn>,
  };

  return (
    <div className="admin-body" style={{ overflow: "hidden", display: "flex", flexDirection: "column" }}>
      <Topbar title={"Editing · " + type} crumbs={["content", item.id]} actions={
        <><Btn icon="external" onClick={() => setPreview(true)}>Preview</Btn><Btn onClick={() => go("content")}>Close</Btn>{status === "review" && <span className="k-chip" style={{ color: "var(--warn)", background: "var(--warn-bg)" }}>publish = human only</span>}</>
      } />
      <div className="editor-grid">
        <div className="editor-main">
          <div className="editor-header">
            <div className="editor-meta-row">
              <StatusBadge status={status} />
              <span>·</span><span>{item.actor === "human" ? "by koopa" : "drafted by " + item.actor}</span>
              {item.quality_score != null && <><span>·</span><span>ai quality {item.quality_score.toFixed(1)}</span></>}
            </div>
            <input className="editor-title-input" value={title} onChange={(e) => setTitle(e.target.value)} />
            <div className="editor-slug-row"><span className="editor-slug-path">koopa0.dev/{type}/</span><span className="editor-slug-val">{item.slug}</span></div>
          </div>
          <div className="editor-area">
            <textarea className="editor-textarea" value={body} onChange={(e) => setBody(e.target.value)} spellCheck={false} />
          </div>
          <div className="editor-footer">
            <span className="editor-footer-count">{body.trim().split(/\s+/).length} words · {Math.max(1, Math.round(body.split(/\s+/).length / 220))} min read</span>
            <span>·</span><AutosaveDot state={save} />
          </div>
        </div>

        <aside className="editor-sidebar">
          <div className="sidebar-section">
            <div className="sidebar-label">Lifecycle</div>
            <div className="lifecycle">
              {CONTENT_STAGES.map((s, i) => (
                <div key={s} className={"lc-step" + (i < stageIdx ? " done" : "") + (i === stageIdx ? " active" : "")}>
                  <span className="lc-node">{i < stageIdx ? <Icon name="check" size={10} stroke={3} /> : i === stageIdx ? <span className="lc-dot" /> : null}</span>
                  <div className="lc-label">{s}</div>
                </div>
              ))}
            </div>
            <div className="lc-actions">{actions[status]}</div>
          </div>

          <div className="sidebar-section">
            <div className="sidebar-label">Visibility</div>
            <Toggle on={isPublic} onClick={() => { setIsPublic(!isPublic); toast(isPublic ? "Set private" : "Set public"); }} />
            <p className="caption" style={{ margin: "8px 0 0", lineHeight: 1.5 }}>{isPublic ? "Live on the public site once published." : "Hidden from the public site. PATCH …/is-public."}</p>
          </div>

          <div className="sidebar-section">
            <div className="sidebar-label">Metadata</div>
            <div className="sidebar-field">
              <label>Type</label>
              <select className="sidebar-select" value={type} onChange={(e) => setType(e.target.value)}>{CONTENT_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
            </div>
            <div className="sidebar-field">
              <label>Topic</label>
              <select className="sidebar-select" value={topic} onChange={(e) => setTopic(e.target.value)}>{TOPICS.map((t) => <option key={t}>{t}</option>)}</select>
            </div>
            <div className="sidebar-field">
              <label>Tags (via tag_aliases)</label>
              <TagInput tags={tags} onAdd={(t) => setTags([...tags, t])} onRemove={(t) => setTags(tags.filter((x) => x !== t))} />
            </div>
          </div>

          {item.quality_score != null && (
            <div className="sidebar-section">
              <div className="sidebar-label">AI metadata <span style={{ color: "var(--fg-faint)", textTransform: "none", letterSpacing: 0 }}>· advisory</span></div>
              <div className="ai-note">
                <div className="ai-note-head"><Icon name="sparkles" size={11} />contents.ai_metadata · quality_score {item.quality_score.toFixed(1)}</div>
                Accurate and well-scoped. Consider a concrete <code style={{ color: "var(--brand)" }}>temp written</code> threshold — currently hand-wavy at “bump work_mem”. The last paragraph restates the intro.
              </div>
            </div>
          )}
        </aside>
      </div>

      {preview && (
        <div className="scrim" onMouseDown={() => setPreview(false)}>
          <div className="preview-frame" onMouseDown={(e) => e.stopPropagation()}>
            <div className="preview-bar">
              <span className="preview-live"><Icon name="external" size={13} /> Publish preview</span>
              <span className="preview-url">koopa0.dev/{type}/{previewSlug}</span>
              <span className="preview-note">renders the live public article component · {status === "published" ? "live" : "draft preview"}</span>
              <span style={{ flex: 1 }} />
              <Btn icon="x" size="sm" onClick={() => setPreview(false)}>Close</Btn>
            </div>
            <iframe className="preview-iframe" src={"koopa.dev.html#/preview/" + previewSlug} title="Publish preview" />
          </div>
        </div>
      )}
    </div>
  );
}
function NoteList({ go }) {
  const [kf, setKf] = e4S("all");
  const rows = K.notes.filter((n) => kf === "all" || n.maturity === kf);
  return (
    <div className="admin-body">
      <Topbar title="Notes" crumbs={["knowledge", "notes"]} actions={<Btn icon="plus" variant="primary" onClick={() => go("note-editor:" + K.notes[0].id)}>New note</Btn>} />
      <div className="content-toolbar">
        <div className="content-chips">
          {["all", ...MATURITIES].map((m) => <button key={m} className={"filter-chip" + (kf === m ? " active" : "")} onClick={() => setKf(m)}>{m}</button>)}
        </div>
        <div style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-subtle)" }}>{rows.length} of {K.notes.length}</div>
      </div>
      <table className="content-table">
        <thead><tr><th>Title</th><th>Kind</th><th>Maturity</th><th>Backlinks</th><th>Words</th><th>Updated</th><th>Slug</th></tr></thead>
        <tbody>
          {rows.map((n) => (
            <tr key={n.id}>
              <td className="cell-title" onClick={() => go("note-editor:" + n.id)}>{n.title}</td>
              <td><span className="cell-type">{n.kind}</span></td>
              <td><span className={"mat-badge mat-" + n.maturity}>{n.maturity.replace("_", " ")}</span></td>
              <td><span className="cell-date">{n.backlinks}</span></td>
              <td><span className="cell-date">{n.words}</span></td>
              <td><span className="cell-date">{n.updated}</span></td>
              <td><span className="cell-id">{n.slug}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------- Note editor ---------- */
function NoteEditor({ id, go, toast }) {
  const note = K.notes.find((n) => n.id === id) || K.notes[0];
  const [title, setTitle] = e4S(note.title);
  const [body, setBody] = e4S(K.noteBody);
  const [kind, setKind] = e4S(note.kind);
  const [maturity, setMaturity] = e4S(note.maturity);
  const save = useAutosave([title, body, kind, maturity]);

  return (
    <div className="admin-body" style={{ overflow: "hidden", display: "flex", flexDirection: "column" }}>
      <Topbar title="Editing note" crumbs={["notes", note.slug]} actions={<Btn onClick={() => go("notes")}>Close</Btn>} />
      <div className="editor-grid">
        <div className="editor-main">
          <div className="editor-header">
            <div className="editor-meta-row">
              <span className={"mat-badge mat-" + maturity}>{maturity.replace("_", " ")}</span>
              <span>·</span><span>{kind}</span><span>·</span><span>{note.backlinks} backlinks</span>
            </div>
            <input className="editor-title-input" value={title} onChange={(e) => setTitle(e.target.value)} />
            <div className="editor-slug-row"><span className="editor-slug-path">notes/</span><span className="editor-slug-val">{note.slug}</span></div>
          </div>
          <div className="editor-area">
            <textarea className="editor-textarea" value={body} onChange={(e) => setBody(e.target.value)} spellCheck={false} />
          </div>
          <div className="editor-footer">
            <span className="editor-footer-count">{body.trim().split(/\s+/).length} words</span>
            <span>·</span><AutosaveDot state={save} />
          </div>
        </div>

        <aside className="editor-sidebar">
          <div className="sidebar-section">
            <div className="sidebar-label">Maturity</div>
            <div className="maturity-list">
              {MATURITIES.map((m) => (
                <button key={m} className={"mat-opt" + (maturity === m ? " sel" : "")} onClick={() => { setMaturity(m); toast("Maturity → " + m.replace("_", " "), "sparkles"); }}>
                  <span className={"mat-swatch mat-" + m} />
                  <span className="mat-name">{m.replace("_", " ")}</span>
                  {maturity === m && <Icon name="check" size={13} style={{ marginLeft: "auto", color: "var(--brand)" }} />}
                </button>
              ))}
            </div>
            <p className="caption" style={{ margin: "10px 0 0", lineHeight: 1.5 }}>A note grows up in place. <span className="k-mono" style={{ color: "var(--fg-muted)" }}>seed</span> → <span className="k-mono" style={{ color: "var(--fg-muted)" }}>evergreen</span>, or retired to <span className="k-mono" style={{ color: "var(--fg-muted)" }}>archived</span>.</p>
          </div>

          <div className="sidebar-section">
            <div className="sidebar-label">Kind</div>
            <div className="sidebar-field">
              <select className="sidebar-select" value={kind} onChange={(e) => setKind(e.target.value)}>{NOTE_KINDS.map((k) => <option key={k}>{k}</option>)}</select>
            </div>
          </div>

          <div className="sidebar-section">
            <div className="sidebar-label">Backlinks</div>
            <div className="sidebar-kv">
              <dt>links in</dt><dd>{note.backlinks}</dd>
              <dt>words</dt><dd>{note.words}</dd>
              <dt>updated</dt><dd>{note.updated}</dd>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}

Object.assign(window, { ContentList, ContentEditor, NoteList, NoteEditor });
