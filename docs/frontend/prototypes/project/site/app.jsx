/* koopa.dev — public reading site app (Zed-docs aesthetic) */
const { useState, useEffect, useRef, useMemo } = React;

const TYPE_DOT = { article: "var(--dot-article)", essay: "var(--dot-essay)", "build-log": "var(--dot-build-log)", til: "var(--dot-til)", digest: "var(--dot-digest)" };
const fmtDate = (s) => { const d = new Date(s); return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };

/* icons */
const SIcon = ({ d, size = 16, stroke = 1.6 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    {(Array.isArray(d) ? d : [d]).map((p, i) => <path key={i} d={p} />)}
  </svg>
);
const IC = {
  search: ["M21 21l-4.3-4.3", "M11 4a7 7 0 1 1 0 14 7 7 0 0 1 0-14z"],
  sun: ["M12 2v2", "M12 20v2", "M4 12H2", "M22 12h-2", "m5 5 1.5 1.5", "m17.5 17.5 1.5 1.5", "m5 19 1.5-1.5", "m17.5 6.5 1.5-1.5", "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"],
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  arrow: ["M5 12h14", "m12 5 7 7-7 7"],
  back: ["M19 12H5", "m12 19-7-7 7-7"],
  hash: ["M4 9h16", "M4 15h16", "M10 3 8 21", "M16 3l-2 18"],
  github: "M9 19c-5 1.5-5-2.5-7-3m14 6v-3.9a3.4 3.4 0 0 0-1-2.6c3-.3 6-1.5 6-6.6a5.1 5.1 0 0 0-1.4-3.5 4.8 4.8 0 0 0-.1-3.5s-1.1-.3-3.5 1.3a12 12 0 0 0-6.4 0C5.3 1.6 4.2 1.9 4.2 1.9a4.8 4.8 0 0 0-.1 3.5A5.1 5.1 0 0 0 2.7 8.9c0 5 3 6.3 5.9 6.6a3.4 3.4 0 0 0-.9 2.6V22",
  external: ["M15 3h6v6", "M10 14 21 3", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"],
  pen: ["M12 20h9", "M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"],
  folder: ["M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9l-.8-1.2A2 2 0 0 0 7.9 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2z"],
};
const Ic = ({ n, size, stroke }) => <SIcon d={IC[n]} size={size} stroke={stroke} />;

const TypeDot = ({ type }) => (
  <span className="post-type" style={{ color: "var(--fg-subtle)" }}>
    <span className="dot" style={{ background: TYPE_DOT[type] || "var(--fg-faint)" }} />{type}
  </span>
);

/* ---------- Post row ---------- */
function Post({ c, go, featured }) {
  return (
    <a className={featured ? "feature" : "post"} onClick={() => go("article:" + c.slug)}>
      <div className="post-meta">
        <TypeDot type={c.type} />
        <span className="post-sep">·</span>
        <span className="post-date">{fmtDate(c.published_at)}</span>
        <span className="post-read">{c.reading_time_min} min</span>
      </div>
      <h3 className="post-title">{c.title}</h3>
      <p className="post-excerpt">{c.excerpt}</p>
    </a>
  );
}

/* ---------- Docs left nav (contextual to the section) ---------- */
function DocsNav({ route, go }) {
  const base = route.split(":")[0], arg = route.split(":")[1];

  // Graph is full-bleed — no side tree
  if (base === "graph") return null;

  // Projects section — the left tree is the project list
  if (base === "projects" || base === "project") {
    return (
      <nav className="docs-nav">
        <div className="docs-nav-group">
          <div className="docs-nav-label">Projects</div>
          {SITE.projects.map((p) => (
            <a key={p.slug} className={"docs-nav-link" + (base === "project" && arg === p.slug ? " active" : "")} onClick={() => go("project:" + p.slug)}>{p.title}</a>
          ))}
        </div>
      </nav>
    );
  }

  // Writing section — the topic → article tree
  return (
    <nav className="docs-nav">
      {SITE.topics.map((t) => {
        const posts = SITE.contents.filter((c) => c.topic === t.slug);
        return (
          <div className="docs-nav-group" key={t.slug}>
            <a className="docs-nav-label" onClick={() => go("topic:" + t.slug)} style={{ cursor: "pointer" }}>
              <span className="dot" style={{ width: 6, height: 6, borderRadius: 99, background: "var(--brand)" }} />{t.name}
            </a>
            {posts.map((c) => (
              <a key={c.slug} className={"docs-nav-link" + (base === "article" && arg === c.slug ? " active" : "")} onClick={() => go("article:" + c.slug)}>
                {c.title}
              </a>
            ))}
          </div>
        );
      })}
    </nav>
  );
}

/* ---------- Home (Articles index) ---------- */
function Home({ go }) {
  const [topic, setTopic] = useState("all");
  const all = [...SITE.contents].sort((a, b) => b.published_at.localeCompare(a.published_at));
  const shown = all.filter((c) => topic === "all" || c.topic === topic);
  return (
    <div className="docs-content">
      <div className="index-hero">
        <div className="home-eyebrow">koopa.dev</div>
        <h1 className="home-title">Let the work speak.</h1>
        <p className="home-lead">{SITE.profile.bio}</p>
      </div>
      <div className="index-filters">
        <button className={"idx-chip" + (topic === "all" ? " active" : "")} onClick={() => setTopic("all")}>All</button>
        {SITE.topics.map((t) => (
          <button key={t.slug} className={"idx-chip" + (topic === t.slug ? " active" : "")} onClick={() => setTopic(t.slug)}>{t.name}</button>
        ))}
      </div>
      <div className="index-list">{shown.map((c) => <Post key={c.slug} c={c} go={go} />)}</div>
    </div>
  );
}

/* ---------- Article ---------- */
function Article({ slug, go }) {
  const c = SITE.contents.find((x) => x.slug === slug) || SITE.contents[0];
  const topic = SITE.topics.find((t) => t.slug === c.topic);
  const rendered = useMemo(() => renderMarkdown(c.body), [c.slug]);
  const related = SITE.contents.filter((x) => x.topic === c.topic && x.slug !== c.slug).slice(0, 2);
  const [activeId, setActiveId] = useState(rendered.toc[0] && rendered.toc[0].id);
  const bodyRef = useRef(null);

  useEffect(() => { window.scrollTo(0, 0); }, [slug]);
  useEffect(() => {
    const onScroll = () => {
      const hs = rendered.toc.map((t) => document.getElementById(t.id)).filter(Boolean);
      let cur = hs[0] && hs[0].id;
      for (const h of hs) { if (h.getBoundingClientRect().top <= 120) cur = h.id; }
      setActiveId(cur);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, [slug]);

  return (
    <div className="reading-wrap">
      <article className="reading-col">
        <div className="reading-crumbs">
          <a onClick={() => go("home")}>koopa.dev</a><span className="sep">/</span>
          <a onClick={() => go("topic:" + c.topic)}>{topic.name}</a><span className="sep">/</span>
          <span style={{ color: "var(--fg-muted)" }}>{c.type}</span>
        </div>
        <div className="article-meta"><TypeDot type={c.type} /><span className="post-sep">·</span><span className="post-date">{fmtDate(c.published_at)}</span><span className="post-sep">·</span><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-faint)" }}>{c.reading_time_min} min read</span></div>
        <h1 className="article-title">{c.title}</h1>
        <p className="article-lead">{c.excerpt}</p>
        <div className="prose" ref={bodyRef} dangerouslySetInnerHTML={{ __html: rendered.html }} />

        <div className="article-foot">
          <div className="article-tags">{c.tags.map((t) => <span key={t} className="article-tag">#{t}</span>)}</div>
          {related.length > 0 && <>
            <div className="readnext-label">Read next</div>
            {related.map((r) => <Post key={r.slug} c={r} go={go} />)}
          </>}
        </div>
      </article>

      <aside className="onpage">
        {rendered.toc.length > 0 && <>
          <div className="onpage-label">On this page</div>
          {rendered.toc.map((t) => (
            <a key={t.id} className={(t.level === 3 ? "lvl3 " : "") + (activeId === t.id ? "active" : "")}
              onClick={() => { const el = document.getElementById(t.id); if (el) window.scrollTo({ top: el.offsetTop - 90, behavior: "smooth" }); }}>{t.text}</a>
          ))}
        </>}
      </aside>
    </div>
  );
}

/* ---------- Topic ---------- */
function Topic({ slug, go }) {
  const t = SITE.topics.find((x) => x.slug === slug) || SITE.topics[0];
  const posts = SITE.contents.filter((c) => c.topic === slug);
  const types = ["all", ...Array.from(new Set(posts.map((p) => p.type)))];
  const [tf, setTf] = useState("all");
  const shown = posts.filter((p) => tf === "all" || p.type === tf);
  const total = Object.values(t.counts).reduce((a, b) => a + b, 0);
  return (
    <div className="docs-content">
      <div className="reading-crumbs" style={{ marginBottom: 20 }}><a onClick={() => go("home")}>koopa.dev</a><span className="sep">/</span><span style={{ color: "var(--fg-muted)" }}>topics</span></div>
      <div className="topic-hero">
        <div className="eyebrow">Topic · {total} pieces</div>
        <h1>{t.name}</h1>
        <p>{t.description}</p>
      </div>
      <div className="topic-typetabs">
        {types.map((ty) => <button key={ty} className={"typetab" + (tf === ty ? " active" : "")} onClick={() => setTf(ty)}>{ty}</button>)}
      </div>
      <div>{shown.map((c) => <Post key={c.slug} c={c} go={go} />)}</div>
    </div>
  );
}

/* ---------- Projects ---------- */
function Projects({ go }) {
  const featured = SITE.projects.find((p) => p.featured) || SITE.projects[0];
  const rest = SITE.projects.filter((p) => p !== featured);
  return (
    <div className="docs-content">
      <div className="reading-crumbs" style={{ marginBottom: 20 }}><a onClick={() => go("home")}>koopa.dev</a><span className="sep">/</span><span style={{ color: "var(--fg-muted)" }}>projects</span></div>
      <div className="topic-hero">
        <div className="eyebrow">Projects</div>
        <h1>What I build</h1>
        <p>Fewer, deeper things. The work is the argument.</p>
      </div>
      <a className="proj-feature" onClick={() => go("project:" + featured.slug)}>
        <div className="proj-feature-top">
          <span className="proj-name lg">{featured.title}</span>
          <span className="proj-role">{featured.role}</span>
        </div>
        <p className="proj-desc">{featured.description}</p>
        {featured.highlights && (
          <ul className="proj-feature-highlights">
            {featured.highlights.slice(0, 3).map((h, i) => <li key={i}><span className="hl-mark" /><span>{h}</span></li>)}
          </ul>
        )}
        <div className="proj-stack">{featured.tech_stack.map((s) => <span key={s} className="proj-tech">{s}</span>)}</div>
        <span className="proj-more">View project <Ic n="arrow" size={13} /></span>
      </a>
      <div className="proj-rest">
        {rest.map((p) => (
          <a key={p.slug} className="proj-row" onClick={() => go("project:" + p.slug)}>
            <div className="proj-row-main">
              <span className="proj-name">{p.title}</span>
              <span className="proj-row-desc">{p.description}</span>
            </div>
            <span className="proj-arrow"><Ic n="arrow" size={15} /></span>
          </a>
        ))}
      </div>
    </div>
  );
}

/* ---------- Project detail ---------- */
function ProjectDetail({ slug, go }) {
  const p = SITE.projects.find((x) => x.slug === slug) || SITE.projects[0];
  const Section = ({ label, children }) => children ? (
    <div className="projd-section">
      <div className="projd-label">{label}</div>
      <p className="projd-text">{children}</p>
    </div>
  ) : null;
  return (
    <div className="docs-content">
      <div className="reading-crumbs" style={{ marginBottom: 22 }}><a onClick={() => go("home")}>koopa.dev</a><span className="sep">/</span><a onClick={() => go("projects")}>projects</a><span className="sep">/</span><span style={{ color: "var(--fg-muted)" }}>{p.slug}</span></div>
      <div className="projd-hero">
        <div className="eyebrow" style={{ fontFamily: "var(--font-mono)", fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--brand)" }}>Project · {p.role}</div>
        <h1 className="projd-title">{p.title}</h1>
        <p className="projd-lead">{p.long_description || p.description}</p>
        <div className="projd-actions">
          {p.live_url && <a className="btn-primary" href={p.live_url}><Ic n="external" size={14} /> Live</a>}
          {p.github_url && <a className="btn-ghost" href={p.github_url}><Ic n="github" size={15} /> Source</a>}
        </div>
        <div className="proj-stack" style={{ marginTop: 20 }}>{p.tech_stack.map((s) => <span key={s} className="proj-tech">{s}</span>)}</div>
      </div>

      <Section label="The problem">{p.problem}</Section>
      <Section label="The approach">{p.solution}</Section>
      <Section label="Architecture">{p.architecture}</Section>
      <Section label="Where it stands">{p.results}</Section>

      {p.highlights && p.highlights.length > 0 && (
        <div className="projd-section">
          <div className="projd-label">Highlights</div>
          <ul className="projd-highlights">
            {p.highlights.map((h, i) => <li key={i}><span className="hl-mark" /><span>{h}</span></li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

/* ---------- Knowledge graph ---------- */
function KnowledgeGraph({ go }) {
  const [hover, setHover] = useState(null);
  const W = 900, H = 560, cx = W / 2, cy = H / 2;
  const nodes = [];
  const edges = [];
  const T = SITE.topics.length;
  SITE.topics.forEach((t, i) => {
    const a = (i / T) * Math.PI * 2 - Math.PI / 2;
    const tx = cx + Math.cos(a) * 195, ty = cy + Math.sin(a) * 150;
    nodes.push({ id: "t:" + t.slug, kind: "topic", label: t.name, x: tx, y: ty, slug: t.slug });
    const posts = SITE.contents.filter((c) => c.topic === t.slug);
    posts.forEach((c, j) => {
      const spread = (posts.length - 1) / 2;
      const ca = a + (j - spread) * 0.42;
      const cxp = tx + Math.cos(ca) * 92, cyp = ty + Math.sin(ca) * 78;
      nodes.push({ id: "c:" + c.slug, kind: "content", label: c.title, x: cxp, y: cyp, slug: c.slug, type: c.type });
      edges.push({ a: "t:" + t.slug, b: "c:" + c.slug });
    });
  });
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const connected = (id) => { if (!id) return new Set(); const s = new Set([id]); edges.forEach((e) => { if (e.a === id) s.add(e.b); if (e.b === id) s.add(e.a); }); return s; };
  const lit = connected(hover);
  const isDim = (id) => hover && !lit.has(id);

  return (
    <div className="docs-content" style={{ maxWidth: 1000 }}>
      <div className="reading-crumbs" style={{ marginBottom: 20 }}><a onClick={() => go("home")}>koopa.dev</a><span className="sep">/</span><span style={{ color: "var(--fg-muted)" }}>graph</span></div>
      <div className="topic-hero" style={{ borderBottom: "none", paddingBottom: 8 }}>
        <div className="eyebrow">Knowledge graph</div>
        <h1>How the ideas connect</h1>
        <p>Every published piece, wired to its topic. Hover a node to trace its neighbourhood; click to read.</p>
      </div>
      <div className="graph-wrap">
        <svg viewBox={`0 0 ${W} ${H}`} className="graph-svg">
          {edges.map((e, i) => {
            const A = byId[e.a], B = byId[e.b];
            const dim = hover && !(lit.has(e.a) && lit.has(e.b));
            return <line key={i} x1={A.x} y1={A.y} x2={B.x} y2={B.y} stroke="var(--border-strong)" strokeWidth={1} opacity={dim ? 0.12 : 0.5} />;
          })}
          {nodes.map((n) => {
            const dim = isDim(n.id);
            const r = n.kind === "topic" ? 9 : 5;
            const color = n.kind === "topic" ? "var(--brand)" : (TYPE_DOT[n.type] || "var(--fg-subtle)");
            return (
              <g key={n.id} className="graph-node" opacity={dim ? 0.3 : 1}
                onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}
                onClick={() => go(n.kind === "topic" ? "topic:" + n.slug : "article:" + n.slug)}>
                <circle cx={n.x} cy={n.y} r={n.kind === "topic" ? 18 : 12} fill="transparent" />
                <circle cx={n.x} cy={n.y} r={r} fill={color} stroke="var(--bg)" strokeWidth={2} />
                {(n.kind === "topic" || hover === n.id || lit.has(n.id)) && (
                  <text x={n.x} y={n.y - (n.kind === "topic" ? 16 : 12)} textAnchor="middle"
                    className={n.kind === "topic" ? "graph-label topic" : "graph-label"}>{n.kind === "topic" ? n.label : (n.label.length > 30 ? n.label.slice(0, 30) + "…" : n.label)}</text>
                )}
              </g>
            );
          })}
        </svg>
        <div className="graph-legend">
          <span className="gl"><span className="gl-dot" style={{ background: "var(--brand)", width: 9, height: 9 }} /> topic</span>
          {Object.entries(TYPE_DOT).map(([k, v]) => <span key={k} className="gl"><span className="gl-dot" style={{ background: v }} /> {k}</span>)}
        </div>
      </div>
    </div>
  );
}

/* ---------- Search ---------- */
function Search({ open, onClose, go }) {
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef(null);
  useEffect(() => { if (open) { setQ(""); setActive(0); setTimeout(() => inputRef.current && inputRef.current.focus(), 20); } }, [open]);
  const results = q.trim()
    ? SITE.contents.filter((c) => (c.title + " " + c.excerpt + " " + c.tags.join(" ")).toLowerCase().includes(q.toLowerCase()))
    : SITE.contents.slice(0, 5);
  useEffect(() => { setActive(0); }, [q]);
  const onKey = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === "Enter") { const r = results[active]; if (r) { go("article:" + r.slug); onClose(); } }
    else if (e.key === "Escape") onClose();
  };
  if (!open) return null;
  return (
    <div className="search-scrim" onMouseDown={onClose}>
      <div className="search-modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="search-modal-input">
          <span style={{ color: "var(--fg-subtle)" }}><Ic n="search" size={17} /></span>
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} placeholder="Search writing…" />
        </div>
        <div className="search-modal-results">
          {results.length === 0 && <div className="search-modal-empty">No matches for “{q}”.</div>}
          {results.map((r, i) => (
            <a key={r.slug} className={"search-modal-item" + (active === i ? " active" : "")} onMouseEnter={() => setActive(i)} onClick={() => { go("article:" + r.slug); onClose(); }}>
              <div className="t">{r.title}</div>
              <div className="s">{r.type} · {r.topic} · {r.reading_time_min} min</div>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ---------- Shell + App ---------- */
const routeToHash = (r) => { const [b, a] = r.split(":"); return "#/" + (b === "home" ? "" : b) + (a ? "/" + a : ""); };
const hashToRoute = () => { const h = location.hash.replace(/^#\/?/, ""); if (!h) return "home"; const [b, a] = h.split("/"); return a ? b + ":" + a : b; };

function App() {
  const [route, setRoute] = useState(hashToRoute());
  const [search, setSearch] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem("koopa-theme") || "dark");
  const go = (r) => { setRoute(r); setSearch(false); if (location.hash !== routeToHash(r)) location.hash = routeToHash(r); };

  useEffect(() => { document.documentElement.setAttribute("data-theme", theme); localStorage.setItem("koopa-theme", theme); }, [theme]);
  useEffect(() => {
    const onHash = () => setRoute(hashToRoute());
    window.addEventListener("hashchange", onHash);
    const onKey = (e) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setSearch((s) => !s); } };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("hashchange", onHash); window.removeEventListener("keydown", onKey); };
  }, []);

  const base = route.split(":")[0], arg = route.split(":")[1];

  // chrome-less preview mode (embedded by the admin publish-preview)
  if (base === "preview") {
    return <div className="site preview-mode"><main className="docs-main"><Article slug={arg} go={() => {}} /></main></div>;
  }

  const page = base === "article" ? <Article slug={arg} go={go} />
    : base === "topic" ? <Topic slug={arg} go={go} />
    : base === "project" ? <ProjectDetail slug={arg} go={go} />
    : base === "projects" ? <Projects go={go} />
    : base === "graph" ? <KnowledgeGraph go={go} />
    : <Home go={go} />;

  return (
    <div className="site">
      <header className="site-header">
        <div className="site-header-inner">
          <a className="brand" onClick={() => go("home")} style={{ cursor: "pointer" }}>
            <img src="assets/logo-title.png" alt="koopa" />
          </a>
          <nav className="nav">
            <a className="navlink" data-active={base === "home" || base === "article" || base === "topic"} onClick={() => go("home")}>Articles</a>
            <a className="navlink" data-active={base === "projects" || base === "project"} onClick={() => go("projects")}>Projects</a>
          </nav>
          <div className="header-spacer" />
          <button className="search-btn" onClick={() => setSearch(true)}><Ic n="search" size={13} /><span className="search-btn-label">Search</span><kbd className="kbd">⌘K</kbd></button>
          <button className="theme-btn" title="Toggle theme" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}><Ic n={theme === "dark" ? "sun" : "moon"} size={16} /></button>
          <a className="icon-btn" href="#" title="GitHub"><Ic n="github" size={17} /></a>
        </div>
      </header>

      <div className="reader">
        <main className="docs-main">{page}</main>
      </div>

      <Search open={search} onClose={() => setSearch(false)} go={go} />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
