/* @ds-bundle: {"format":3,"namespace":"KoopaDevDesignSystem_5c9a29","components":[],"sourceHashes":{"ui_kits/public-site/Article.jsx":"16e973849793","ui_kits/public-site/Home.jsx":"ceda56dc632e","ui_kits/public-site/Icons.jsx":"1b3eb41a08d6","ui_kits/public-site/SearchPage.jsx":"16f5371279cb","ui_kits/public-site/Shell.jsx":"7f0225b870b4","ui_kits/public-site/Topic.jsx":"b635f6d0ff0f","ui_kits/public-site/bundle.jsx":"ef4671b85d6b","ui_kits/public-site/data.jsx":"ff44ad315879"},"inlinedExternals":[],"unexposedExports":[]} */

(() => {

const __ds_ns = (window.KoopaDevDesignSystem_5c9a29 = window.KoopaDevDesignSystem_5c9a29 || {});

const __ds_scope = {};

(__ds_ns.__errors = __ds_ns.__errors || []);

// ui_kits/public-site/Article.jsx
try { (() => {
const {
  CONTENT,
  CONTENT_TYPES
} = window;
function Article({
  slug,
  setRoute
}) {
  const item = CONTENT.find(c => c.slug === slug) || CONTENT[0];
  const t = CONTENT_TYPES[item.type];
  return /*#__PURE__*/React.createElement("main", {
    className: "page-reading"
  }, /*#__PURE__*/React.createElement("div", {
    className: "reading-inner"
  }, /*#__PURE__*/React.createElement("nav", {
    className: "breadcrumbs"
  }, /*#__PURE__*/React.createElement("a", {
    onClick: e => {
      e.preventDefault();
      setRoute('home');
    },
    href: "#"
  }, "koopa0.dev"), /*#__PURE__*/React.createElement("span", null, "/"), /*#__PURE__*/React.createElement("a", {
    onClick: e => {
      e.preventDefault();
      setRoute('articles');
    },
    href: "#"
  }, "writing"), /*#__PURE__*/React.createElement("span", null, "/"), /*#__PURE__*/React.createElement("span", {
    className: "current"
  }, item.slug)), /*#__PURE__*/React.createElement("header", {
    className: "reading-header"
  }, /*#__PURE__*/React.createElement("div", {
    className: "reading-meta"
  }, /*#__PURE__*/React.createElement("span", {
    className: "type-dot-row"
  }, /*#__PURE__*/React.createElement("span", {
    className: "type-dot",
    style: {
      background: t.dot
    }
  }), /*#__PURE__*/React.createElement("span", {
    className: "type-label"
  }, t.label)), /*#__PURE__*/React.createElement("span", {
    className: "meta-sep"
  }, "\xB7"), /*#__PURE__*/React.createElement("span", null, item.date), /*#__PURE__*/React.createElement("span", {
    className: "meta-sep"
  }, "\xB7"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement(Clock, {
    size: 12
  }), " ", item.read, " min"), /*#__PURE__*/React.createElement("span", {
    className: "meta-sep"
  }, "\xB7"), /*#__PURE__*/React.createElement("a", {
    onClick: e => {
      e.preventDefault();
      setRoute('topic/' + item.topic);
    },
    href: "#",
    className: "topic-link"
  }, item.topic)), /*#__PURE__*/React.createElement("h1", {
    className: "reading-title"
  }, item.title), /*#__PURE__*/React.createElement("p", {
    className: "reading-lead"
  }, item.summary)), /*#__PURE__*/React.createElement("article", {
    className: "prose"
  }, /*#__PURE__*/React.createElement("h2", null, "Go's concurrency model"), /*#__PURE__*/React.createElement("p", null, "Most languages bolt concurrency on. Go was designed around it. Goroutines are not threads \u2014 they're lightweight, M:N scheduled onto OS threads by the runtime, with a few KB of initial stack that grows on demand. You can launch ten thousand of them without panicking the scheduler."), /*#__PURE__*/React.createElement("p", null, "But cheap concurrency is a trap if you don't have a way to coordinate. That's where channels come in. The CSP model says: ", /*#__PURE__*/React.createElement("em", null, "don't communicate by sharing memory; share memory by communicating"), ". Channels are the communication primitive."), /*#__PURE__*/React.createElement("h3", null, "A first goroutine"), /*#__PURE__*/React.createElement("pre", null, /*#__PURE__*/React.createElement("code", null, `func worker(id int) {
    fmt.Printf("worker %d starting\\n", id)
    time.Sleep(time.Second)
    fmt.Printf("worker %d done\\n", id)
}

func main() {
    for i := 1; i <= 5; i++ {
        go worker(i)
    }
    time.Sleep(2 * time.Second)
}`)), /*#__PURE__*/React.createElement("p", null, "This prints interleaved output, because five workers run concurrently. But the final ", /*#__PURE__*/React.createElement("code", null, "time.Sleep"), " is a smell \u2014 we're using wall clock to coordinate instead of a primitive. The fix is almost always a ", /*#__PURE__*/React.createElement("code", null, "WaitGroup"), " or a done-channel."), /*#__PURE__*/React.createElement("h3", null, "When channels are right"), /*#__PURE__*/React.createElement("p", null, "Channels are the right tool when you need to pass ownership of data, or synchronise a handoff between goroutines. They're the wrong tool for protecting a shared counter \u2014 that's what ", /*#__PURE__*/React.createElement("code", null, "sync/atomic"), " and ", /*#__PURE__*/React.createElement("code", null, "sync.Mutex"), " are for."), /*#__PURE__*/React.createElement("blockquote", null, "I keep making the same mistake: reaching for a channel when a mutex would do. Channels look elegant; mutexes look crude. But crude tools are often correct."), /*#__PURE__*/React.createElement("h3", null, "Select & timeouts"), /*#__PURE__*/React.createElement("p", null, "Every real system needs timeouts. ", /*#__PURE__*/React.createElement("code", null, "select"), " with ", /*#__PURE__*/React.createElement("code", null, "time.After"), " is the idiom. Don't build this yourself with goroutines and flags \u2014 you'll get it wrong.")), /*#__PURE__*/React.createElement("aside", {
    className: "reading-footer"
  }, /*#__PURE__*/React.createElement("div", {
    className: "reading-tags"
  }, item.tags.map(t => /*#__PURE__*/React.createElement("span", {
    key: t,
    className: "tag"
  }, "#", t))), /*#__PURE__*/React.createElement("div", {
    className: "reading-meta"
  }, "Last edited ", /*#__PURE__*/React.createElement("span", {
    className: "mono"
  }, "2026-03-22")))), /*#__PURE__*/React.createElement("aside", {
    className: "toc"
  }, /*#__PURE__*/React.createElement("div", {
    className: "toc-label"
  }, "On this page"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "toc-item active"
  }, "Go's concurrency model"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "toc-item indent"
  }, "A first goroutine"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "toc-item indent"
  }, "When channels are right"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "toc-item indent"
  }, "Select & timeouts")));
}
window.Article = Article;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/public-site/Article.jsx", error: String((e && e.message) || e) }); }

// ui_kits/public-site/Home.jsx
try { (() => {
const {
  TOPICS,
  CONTENT,
  ContentRow,
  TopicCard
} = window;
function Home({
  setRoute
}) {
  return /*#__PURE__*/React.createElement("main", {
    className: "page"
  }, /*#__PURE__*/React.createElement("section", {
    className: "hero"
  }, /*#__PURE__*/React.createElement("div", {
    className: "hero-eyebrow"
  }, /*#__PURE__*/React.createElement(Hex, {
    size: 12,
    stroke: "var(--brand)"
  }), " ", /*#__PURE__*/React.createElement("span", null, "A personal knowledge engine")), /*#__PURE__*/React.createElement("h1", {
    className: "hero-title"
  }, "I'm building in public.", /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("span", {
    className: "hero-muted"
  }, "Here's the work, organised by topic.")), /*#__PURE__*/React.createElement("p", {
    className: "hero-lead"
  }, "Not a blog. Not a portfolio. A semantic runtime that multiple AI agents share \u2014 goals, projects, tasks, learning observations, content \u2014 coordinating to help one developer think better over time."), /*#__PURE__*/React.createElement("div", {
    className: "hero-cta"
  }, /*#__PURE__*/React.createElement("a", {
    className: "btn-primary",
    onClick: e => {
      e.preventDefault();
      setRoute('topics');
    },
    href: "#"
  }, "Browse topics ", /*#__PURE__*/React.createElement(ArrowRight, {
    size: 14
  })), /*#__PURE__*/React.createElement("a", {
    className: "btn-ghost",
    onClick: e => {
      e.preventDefault();
      setRoute('about');
    },
    href: "#"
  }, "What is this?"))), /*#__PURE__*/React.createElement("section", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-head"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "section-title"
  }, "Topics"), /*#__PURE__*/React.createElement("p", {
    className: "section-sub"
  }, "The work is organised by idea, not by date.")), /*#__PURE__*/React.createElement("div", {
    className: "topics-grid"
  }, TOPICS.slice(0, 6).map(t => /*#__PURE__*/React.createElement(TopicCard, {
    key: t.slug,
    topic: t,
    setRoute: setRoute
  })))), /*#__PURE__*/React.createElement("section", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "section-head"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "section-title"
  }, "Recently"), /*#__PURE__*/React.createElement("p", {
    className: "section-sub"
  }, "Drafts become public only after review. Most of what I write stays private.")), /*#__PURE__*/React.createElement("div", {
    className: "content-list"
  }, CONTENT.slice(0, 6).map(c => /*#__PURE__*/React.createElement(ContentRow, {
    key: c.slug,
    item: c,
    setRoute: setRoute
  })))), /*#__PURE__*/React.createElement("section", {
    className: "section callout"
  }, /*#__PURE__*/React.createElement("div", {
    className: "callout-inner"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "callout-label"
  }, "Now"), /*#__PURE__*/React.createElement("p", {
    className: "callout-body"
  }, "Rewriting the content pipeline as a single Genkit flow. Studying FSRS to stop over-reviewing easy items. Reading Dunlosky on retrieval practice, again.")), /*#__PURE__*/React.createElement("div", {
    className: "callout-meta"
  }, /*#__PURE__*/React.createElement("span", null, "Last updated"), /*#__PURE__*/React.createElement("span", {
    className: "mono"
  }, "2026-04-18")))));
}
window.Home = Home;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/public-site/Home.jsx", error: String((e && e.message) || e) }); }

// ui_kits/public-site/Icons.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
// Shared icons + tiny UI primitives for public site
const Icon = ({
  d,
  size = 18,
  stroke = 1.5,
  fill = "none"
}) => /*#__PURE__*/React.createElement("svg", {
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: fill,
  stroke: "currentColor",
  strokeWidth: stroke,
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, Array.isArray(d) ? d.map((p, i) => /*#__PURE__*/React.createElement("path", {
  key: i,
  d: p
})) : /*#__PURE__*/React.createElement("path", {
  d: d
}));
const Hex = ({
  size = 18,
  fill = "none",
  stroke = "currentColor"
}) => /*#__PURE__*/React.createElement("svg", {
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: fill,
  stroke: stroke,
  strokeWidth: "1.5",
  strokeLinejoin: "round"
}, /*#__PURE__*/React.createElement("polygon", {
  points: "12,2 22,8 22,16 12,22 2,16 2,8"
}));
const Search = p => /*#__PURE__*/React.createElement(Icon, _extends({}, p, {
  d: ["M21 21l-4.3-4.3", "M11 4a7 7 0 1 1 0 14 7 7 0 0 1 0-14z"]
}));
const ChevronDown = p => /*#__PURE__*/React.createElement(Icon, _extends({}, p, {
  d: "m6 9 6 6 6-6"
}));
const ArrowRight = p => /*#__PURE__*/React.createElement(Icon, _extends({}, p, {
  d: ["M5 12h14", "m12 5 7 7-7 7"]
}));
const Clock = p => /*#__PURE__*/React.createElement(Icon, _extends({}, p, {
  d: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 6v6l4 2"]
}));
const Github = p => /*#__PURE__*/React.createElement(Icon, _extends({}, p, {
  d: "M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21"
}));
const Mail = p => /*#__PURE__*/React.createElement(Icon, _extends({}, p, {
  d: ["M22 4H2v16h20V4z", "m2 6 10 7 10-7"]
}));
const Rss = p => /*#__PURE__*/React.createElement(Icon, _extends({}, p, {
  d: ["M4 11a9 9 0 0 1 9 9", "M4 4a16 16 0 0 1 16 16"]
}));
const Hash = p => /*#__PURE__*/React.createElement(Icon, _extends({}, p, {
  d: ["M4 9h16", "M4 15h16", "m10 3-2 18", "m16 3-2 18"]
}));
window.Icon = Icon;
window.Hex = Hex;
window.Search = Search;
window.ChevronDown = ChevronDown;
window.ArrowRight = ArrowRight;
window.Clock = Clock;
window.Github = Github;
window.Mail = Mail;
window.Rss = Rss;
window.Hash = Hash;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/public-site/Icons.jsx", error: String((e && e.message) || e) }); }

// ui_kits/public-site/SearchPage.jsx
try { (() => {
const {
  CONTENT,
  TOPICS,
  CONTENT_TYPES
} = window;
function SearchPage({
  setRoute
}) {
  const [q, setQ] = React.useState("goroutine");
  const results = CONTENT.filter(c => !q || c.title.toLowerCase().includes(q.toLowerCase()) || c.summary.toLowerCase().includes(q.toLowerCase()) || c.tags.some(t => t.includes(q.toLowerCase())));
  const topicHits = TOPICS.filter(t => !q || t.name.toLowerCase().includes(q.toLowerCase()));
  return /*#__PURE__*/React.createElement("main", {
    className: "page"
  }, /*#__PURE__*/React.createElement("section", {
    className: "search-shell"
  }, /*#__PURE__*/React.createElement("div", {
    className: "search-box"
  }, /*#__PURE__*/React.createElement(Search, {
    size: 18
  }), /*#__PURE__*/React.createElement("input", {
    autoFocus: true,
    value: q,
    onChange: e => setQ(e.target.value),
    placeholder: "Search articles, essays, notes\u2026"
  }), /*#__PURE__*/React.createElement("kbd", {
    className: "kbd"
  }, "esc")), /*#__PURE__*/React.createElement("div", {
    className: "search-chips"
  }, /*#__PURE__*/React.createElement("span", {
    className: "chip"
  }, "type:article"), /*#__PURE__*/React.createElement("span", {
    className: "chip"
  }, "topic:go-concurrency"), /*#__PURE__*/React.createElement("span", {
    className: "chip"
  }, "tag:postgres"), /*#__PURE__*/React.createElement("span", {
    className: "chip"
  }, "semantic"), /*#__PURE__*/React.createElement("span", {
    className: "chip"
  }, "full-text"))), /*#__PURE__*/React.createElement("section", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "search-section-head"
  }, /*#__PURE__*/React.createElement("span", {
    className: "eyebrow"
  }, "Topics"), /*#__PURE__*/React.createElement("span", {
    className: "muted"
  }, topicHits.length, " match")), /*#__PURE__*/React.createElement("div", {
    className: "search-topic-row"
  }, topicHits.slice(0, 4).map(t => /*#__PURE__*/React.createElement("a", {
    key: t.slug,
    href: "#",
    onClick: e => {
      e.preventDefault();
      setRoute('topic/' + t.slug);
    },
    className: "search-topic-pill"
  }, /*#__PURE__*/React.createElement(Hex, {
    size: 14,
    stroke: "var(--brand)"
  }), /*#__PURE__*/React.createElement("span", null, t.name), /*#__PURE__*/React.createElement("span", {
    className: "search-topic-count"
  }, Object.values(t.counts).reduce((a, b) => a + b, 0)))))), /*#__PURE__*/React.createElement("section", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "search-section-head"
  }, /*#__PURE__*/React.createElement("span", {
    className: "eyebrow"
  }, "Content"), /*#__PURE__*/React.createElement("span", {
    className: "muted"
  }, results.length, " match \xB7 sorted by relevance")), /*#__PURE__*/React.createElement("div", {
    className: "search-results"
  }, results.map(r => {
    const t = CONTENT_TYPES[r.type];
    return /*#__PURE__*/React.createElement("a", {
      key: r.slug,
      href: "#",
      onClick: e => {
        e.preventDefault();
        setRoute('article/' + r.slug);
      },
      className: "search-result"
    }, /*#__PURE__*/React.createElement("div", {
      className: "search-result-head"
    }, /*#__PURE__*/React.createElement("span", {
      className: "type-dot",
      style: {
        background: t.dot
      }
    }), /*#__PURE__*/React.createElement("span", {
      className: "type-label"
    }, t.label), /*#__PURE__*/React.createElement("span", {
      className: "meta-sep"
    }, "\xB7"), /*#__PURE__*/React.createElement("span", {
      className: "muted"
    }, r.date), /*#__PURE__*/React.createElement("span", {
      className: "meta-sep"
    }, "\xB7"), /*#__PURE__*/React.createElement("span", {
      className: "mono muted"
    }, r.topic)), /*#__PURE__*/React.createElement("div", {
      className: "search-result-title"
    }, r.title), /*#__PURE__*/React.createElement("div", {
      className: "search-result-summary"
    }, r.summary));
  }))));
}
window.SearchPage = SearchPage;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/public-site/SearchPage.jsx", error: String((e && e.message) || e) }); }

// ui_kits/public-site/Shell.jsx
try { (() => {
const {
  TOPICS,
  CONTENT,
  CONTENT_TYPES
} = window;
function Header({
  route,
  setRoute
}) {
  const link = (id, label) => /*#__PURE__*/React.createElement("a", {
    onClick: e => {
      e.preventDefault();
      setRoute(id);
    },
    href: "#",
    className: "navlink",
    "data-active": route === id || id === "topics" && route.startsWith("topic/") || id === "articles" && route.startsWith("article/")
  }, label);
  return /*#__PURE__*/React.createElement("header", {
    className: "site-header"
  }, /*#__PURE__*/React.createElement("div", {
    className: "site-header-inner"
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: e => {
      e.preventDefault();
      setRoute("home");
    },
    className: "brand"
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/logo.png",
    width: "28",
    height: "28",
    alt: ""
  }), /*#__PURE__*/React.createElement("span", null, "koopa0.dev")), /*#__PURE__*/React.createElement("nav", {
    className: "nav"
  }, link("home", "Home"), link("articles", "Writing"), link("lab", "Lab"), link("topics", "Topics"), link("projects", "Projects"), link("about", "About")), /*#__PURE__*/React.createElement("button", {
    className: "search-btn",
    onClick: () => setRoute("search")
  }, /*#__PURE__*/React.createElement(Search, {
    size: 16
  }), /*#__PURE__*/React.createElement("span", {
    className: "search-btn-label"
  }, "Search"), /*#__PURE__*/React.createElement("kbd", {
    className: "kbd"
  }, "\u2318/"))));
}
function Footer() {
  return /*#__PURE__*/React.createElement("footer", {
    className: "site-footer"
  }, /*#__PURE__*/React.createElement("div", {
    className: "site-footer-inner"
  }, /*#__PURE__*/React.createElement("div", {
    className: "footer-brand"
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/logo.png",
    width: "22",
    height: "22",
    alt: ""
  }), /*#__PURE__*/React.createElement("span", null, "\xA9 2026 koopa0.dev"), /*#__PURE__*/React.createElement("span", {
    className: "sep"
  }, "\xB7"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "foot-link"
  }, "Privacy"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "foot-link"
  }, "Terms"), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "foot-link"
  }, "Uses")), /*#__PURE__*/React.createElement("div", {
    className: "footer-social"
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "icon-btn"
  }, /*#__PURE__*/React.createElement(Github, {
    size: 16
  })), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "icon-btn"
  }, /*#__PURE__*/React.createElement(Rss, {
    size: 16
  })), /*#__PURE__*/React.createElement("a", {
    href: "#",
    className: "icon-btn"
  }, /*#__PURE__*/React.createElement(Mail, {
    size: 16
  })))));
}
function TypeDot({
  type
}) {
  const t = CONTENT_TYPES[type];
  return /*#__PURE__*/React.createElement("span", {
    className: "type-dot-row"
  }, /*#__PURE__*/React.createElement("span", {
    className: "type-dot",
    style: {
      background: t.dot
    }
  }), " ", /*#__PURE__*/React.createElement("span", {
    className: "type-label"
  }, t.label));
}
function ContentRow({
  item,
  setRoute
}) {
  return /*#__PURE__*/React.createElement("article", {
    className: "content-row",
    onClick: () => setRoute(`article/${item.slug}`)
  }, /*#__PURE__*/React.createElement("div", {
    className: "content-row-meta"
  }, /*#__PURE__*/React.createElement(TypeDot, {
    type: item.type
  }), /*#__PURE__*/React.createElement("span", {
    className: "meta-sep"
  }, "\xB7"), /*#__PURE__*/React.createElement("span", {
    className: "meta-date"
  }, item.date), /*#__PURE__*/React.createElement("span", {
    className: "meta-spacer"
  }), /*#__PURE__*/React.createElement("span", {
    className: "meta-read"
  }, /*#__PURE__*/React.createElement(Clock, {
    size: 12
  }), " ", item.read, " min")), /*#__PURE__*/React.createElement("h3", {
    className: "content-row-title"
  }, item.title), /*#__PURE__*/React.createElement("p", {
    className: "content-row-summary"
  }, item.summary), /*#__PURE__*/React.createElement("div", {
    className: "content-row-tags"
  }, item.tags.map(t => /*#__PURE__*/React.createElement("span", {
    key: t,
    className: "tag"
  }, "#", t))));
}
function TopicCard({
  topic,
  setRoute
}) {
  const total = Object.values(topic.counts).reduce((a, b) => a + b, 0);
  return /*#__PURE__*/React.createElement("a", {
    className: "topic-card",
    onClick: e => {
      e.preventDefault();
      setRoute(`topic/${topic.slug}`);
    },
    href: "#"
  }, /*#__PURE__*/React.createElement("div", {
    className: "topic-hex"
  }, /*#__PURE__*/React.createElement(Hex, {
    size: 22,
    stroke: "var(--brand)"
  })), /*#__PURE__*/React.createElement("div", {
    className: "topic-body"
  }, /*#__PURE__*/React.createElement("h4", {
    className: "topic-name"
  }, topic.name), /*#__PURE__*/React.createElement("p", {
    className: "topic-desc"
  }, topic.desc), /*#__PURE__*/React.createElement("div", {
    className: "topic-counts"
  }, Object.entries(topic.counts).map(([type, n]) => /*#__PURE__*/React.createElement("span", {
    key: type,
    className: "topic-count"
  }, /*#__PURE__*/React.createElement("span", {
    className: "type-dot sm",
    style: {
      background: CONTENT_TYPES[type].dot
    }
  }), n, " ", type)))), /*#__PURE__*/React.createElement("div", {
    className: "topic-total"
  }, /*#__PURE__*/React.createElement("span", null, total), /*#__PURE__*/React.createElement("span", {
    className: "topic-total-label"
  }, "items")));
}
window.Header = Header;
window.Footer = Footer;
window.TypeDot = TypeDot;
window.ContentRow = ContentRow;
window.TopicCard = TopicCard;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/public-site/Shell.jsx", error: String((e && e.message) || e) }); }

// ui_kits/public-site/Topic.jsx
try { (() => {
const {
  TOPICS,
  CONTENT,
  CONTENT_TYPES,
  ContentRow,
  TopicCard
} = window;
function Topic({
  slug,
  setRoute
}) {
  const topic = TOPICS.find(t => t.slug === slug) || TOPICS[0];
  const items = CONTENT.filter(c => c.topic === topic.slug).concat(CONTENT).slice(0, 6);
  return /*#__PURE__*/React.createElement("main", {
    className: "page"
  }, /*#__PURE__*/React.createElement("nav", {
    className: "breadcrumbs page-crumbs"
  }, /*#__PURE__*/React.createElement("a", {
    onClick: e => {
      e.preventDefault();
      setRoute('home');
    },
    href: "#"
  }, "koopa0.dev"), /*#__PURE__*/React.createElement("span", null, "/"), /*#__PURE__*/React.createElement("a", {
    onClick: e => {
      e.preventDefault();
      setRoute('topics');
    },
    href: "#"
  }, "topics"), /*#__PURE__*/React.createElement("span", null, "/"), /*#__PURE__*/React.createElement("span", {
    className: "current"
  }, topic.slug)), /*#__PURE__*/React.createElement("section", {
    className: "topic-header"
  }, /*#__PURE__*/React.createElement("div", {
    className: "topic-header-hex"
  }, /*#__PURE__*/React.createElement(Hex, {
    size: 32,
    stroke: "var(--brand)",
    fill: "var(--brand-faint)"
  })), /*#__PURE__*/React.createElement("div", {
    className: "topic-header-body"
  }, /*#__PURE__*/React.createElement("div", {
    className: "eyebrow"
  }, "Topic"), /*#__PURE__*/React.createElement("h1", {
    className: "topic-title"
  }, topic.name), /*#__PURE__*/React.createElement("p", {
    className: "topic-desc-large"
  }, topic.desc), /*#__PURE__*/React.createElement("div", {
    className: "topic-counts-row"
  }, Object.entries(topic.counts).map(([type, n]) => /*#__PURE__*/React.createElement("span", {
    key: type,
    className: "topic-count-chip"
  }, /*#__PURE__*/React.createElement("span", {
    className: "type-dot sm",
    style: {
      background: CONTENT_TYPES[type].dot
    }
  }), n, " ", type))))), /*#__PURE__*/React.createElement("section", {
    className: "section"
  }, /*#__PURE__*/React.createElement("div", {
    className: "topic-filter-tabs"
  }, /*#__PURE__*/React.createElement("button", {
    className: "tab active"
  }, "All"), /*#__PURE__*/React.createElement("button", {
    className: "tab"
  }, "Articles"), /*#__PURE__*/React.createElement("button", {
    className: "tab"
  }, "Build logs"), /*#__PURE__*/React.createElement("button", {
    className: "tab"
  }, "TIL"), /*#__PURE__*/React.createElement("button", {
    className: "tab"
  }, "Notes")), /*#__PURE__*/React.createElement("div", {
    className: "content-list"
  }, items.map(c => /*#__PURE__*/React.createElement(ContentRow, {
    key: c.slug,
    item: c,
    setRoute: setRoute
  })))), /*#__PURE__*/React.createElement("section", {
    className: "section"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "h3"
  }, "Related topics"), /*#__PURE__*/React.createElement("div", {
    className: "topics-grid"
  }, TOPICS.filter(t => t.slug !== topic.slug).slice(0, 3).map(t => /*#__PURE__*/React.createElement(TopicCard, {
    key: t.slug,
    topic: t,
    setRoute: setRoute
  })))));
}
window.Topic = Topic;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/public-site/Topic.jsx", error: String((e && e.message) || e) }); }

// ui_kits/public-site/data.jsx
try { (() => {
// Shared data for public site
window.TOPICS = [{
  slug: "go-concurrency",
  name: "Go concurrency",
  desc: "Goroutines, channels, select, worker pools. The deep end.",
  counts: {
    article: 14,
    til: 6,
    "build-log": 3
  }
}, {
  slug: "ai-coaching",
  name: "AI coaching",
  desc: "Using LLMs as a thinking partner, not an autocomplete.",
  counts: {
    essay: 7,
    article: 4,
    note: 12
  }
}, {
  slug: "pg-performance",
  name: "Postgres performance",
  desc: "Explain plans, vacuum, partial indexes, pgvector.",
  counts: {
    article: 8,
    til: 15,
    bookmark: 4
  }
}, {
  slug: "angular-signals",
  name: "Angular signals",
  desc: "Reactive primitives after the RxJS tax.",
  counts: {
    article: 5,
    "build-log": 2
  }
}, {
  slug: "learning-engine",
  name: "Learning engine",
  desc: "Spaced repetition + cognitive observations = deliberate practice.",
  counts: {
    essay: 3,
    article: 4,
    note: 22
  }
}, {
  slug: "obsidian-pipeline",
  name: "Obsidian pipeline",
  desc: "Markdown as source of truth, site as presentation layer.",
  counts: {
    "build-log": 9,
    note: 18
  }
}];
window.CONTENT = [{
  type: "article",
  title: "Golang concurrency: goroutines & channels",
  slug: "go-concurrency-goroutines-channels",
  topic: "go-concurrency",
  date: "2025-03-14",
  read: 8,
  summary: "A walkthrough of Go's CSP model — when channels help, when they get in the way, and the mistakes I keep making.",
  tags: ["go", "channels", "csp"]
}, {
  type: "essay",
  title: "The cost of auto-carryover",
  slug: "auto-carryover-cost",
  topic: "learning-engine",
  date: "2025-03-11",
  read: 5,
  summary: "Why I refuse to let yesterday's tasks silently roll into today. Friction is a feature, not a bug.",
  tags: ["gtd", "workflow"]
}, {
  type: "til",
  title: "Postgres EXPLAIN (ANALYZE, BUFFERS)",
  slug: "pg-explain-buffers",
  topic: "pg-performance",
  date: "2025-03-09",
  read: 2,
  summary: "BUFFERS tells you what memory the query touched. Often more useful than the plan itself.",
  tags: ["postgres"]
}, {
  type: "build-log",
  title: "Rewriting the pipeline as a Genkit flow",
  slug: "genkit-pipeline",
  topic: "obsidian-pipeline",
  date: "2025-03-07",
  read: 12,
  summary: "Day 3 of moving classification and drafting into a single traceable Genkit flow. Observability wins over cleverness.",
  tags: ["genkit", "go"]
}, {
  type: "article",
  title: "Angular signals without RxJS brain damage",
  slug: "signals-without-rxjs",
  topic: "angular-signals",
  date: "2025-03-04",
  read: 10,
  summary: "Signals don't replace observables. But they do let you delete 60% of the observable code you were tolerating.",
  tags: ["angular", "signals"]
}, {
  type: "note",
  title: "pgvector ivfflat vs hnsw",
  slug: "pgvector-index-choice",
  topic: "pg-performance",
  date: "2025-03-02",
  read: 3,
  summary: "Tradeoff cheatsheet. hnsw is usually right; ivfflat wins on build time.",
  tags: ["postgres", "pgvector"]
}, {
  type: "bookmark",
  title: "Russ Cox — Concurrency is not parallelism",
  slug: "rob-pike-concurrency",
  topic: "go-concurrency",
  date: "2025-02-28",
  read: 1,
  summary: "The canonical talk. I come back to it every few months and see something new.",
  tags: ["go"]
}, {
  type: "digest",
  title: "Week 10 — pipeline rewrite, CKA prep",
  slug: "week-10",
  topic: "learning-engine",
  date: "2025-02-24",
  read: 4,
  summary: "What shipped, what stalled, and one hypothesis that got invalidated.",
  tags: ["digest"]
}];
window.CONTENT_TYPES = {
  "article": {
    label: "article",
    dot: "var(--dot-article)"
  },
  "essay": {
    label: "essay",
    dot: "var(--dot-essay)"
  },
  "build-log": {
    label: "build-log",
    dot: "var(--dot-build-log)"
  },
  "til": {
    label: "til",
    dot: "var(--dot-til)"
  },
  "note": {
    label: "note",
    dot: "var(--dot-note)"
  },
  "bookmark": {
    label: "bookmark",
    dot: "var(--dot-bookmark)"
  },
  "digest": {
    label: "digest",
    dot: "var(--dot-digest)"
  }
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/public-site/data.jsx", error: String((e && e.message) || e) }); }

})();
