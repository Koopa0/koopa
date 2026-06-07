# koopa.dev Design System

A design system for **koopa.dev** — a personal knowledge engine that ingests, processes and presents one developer's work and thinking. This system covers the public reader-facing site and the private, tool-dense admin CMS.

> "A quiet instrument." Not startup-bright, not cyberpunk-neon. A workshop, not a showroom.

## Sources

- **Repo:** `Koopa0/koopa` (private). The Angular 21 frontend lives under `frontend/` with Tailwind v4 in `frontend/src/styles.css`, the shell layout in `frontend/src/app/app.html`, and real article content in `frontend/public/content/articles/`.
- **Brand docs:** `README.md` (product positioning, tone) and `CLAUDE.md` (content types, tech stack).
- **Logo + glyph:** `frontend/public/logo.png`, `logo-title.png`, `logo-notitle.png`, `koopa.png` — all imported into `assets/`.
- **Brief:** greenfield exploration of public site, admin UI, and design system; dark mode default, light mode supported.

## Product, in one paragraph

koopa is **not a blog**. It is a semantic runtime — goals, projects, tasks, learning observations, content — that multiple AI agents read from and write to through MCP. The public site is the selectively-published tip of that iceberg (articles, essays, build-logs, TILs, notes, bookmarks, digests), organised by **topic**, not by date. The admin is a dense workspace the owner uses daily to review AI drafts, curate RSS, manage the learning engine (FSRS spaced repetition + cognitive observations), and run the content pipeline.

Two users, two completely different pressures on the system:
1. **Koopa (owner)** lives in the admin — needs Linear / Notion-admin density.
2. **Visitors** (developers, peers) arrive with intent — need calm, long-form legibility.

One design system has to serve both without compromising either.

---

## Content fundamentals

Voice is **writerly, opinionated, slightly weird, human**. The product README is the clearest voice reference.

**Tone guide:**
- **Prose > slogans.** Sentences are long when they need to be. Headings are declarative, not hype-y. "How it works" beats "Features that accelerate you."
- **Opinionated, with reasoning.** Every design-philosophy claim is followed by *why*. Example from the source README: "a system that makes decisions for you eventually makes you worse at making decisions yourself." Don't ship a bullet without the thinking behind it.
- **Precise vocabulary.** Words have defined meanings: *Goal ≠ Project ≠ Todo*. *Task ≠ Todo*. *Attempt ≠ Plan completion*. *Observation ≠ Hypothesis*. This system avoids jargon buzzwords but is rigorous about its own terminology.
- **Technical without bragging.** Names tools by name (Genkit, pgvector, FSRS, MCP) without jargon-dropping. Mentions Go stdlib-first, no frameworks, no DDD.
- **Sparingly poetic.** Phrases like "a quiet instrument", "let the work speak", "the system preserves your ownership". Use once per page; never twice.
- **Person:** first-person singular on the public site ("I", "my"). Second-person "you" on admin when addressing the owner. Never "we" — it's one person.
- **Casing:** Sentence case for titles. `Build Log`, not `BUILD LOG`. Product/agent names are capitalised (HQ, Content Studio, Learning Studio, Claude Code).
- **Dates:** Relative on admin ("2 days ago", "in review"). Absolute on public pages (`2025-03-14` ISO, or `Mar 14, 2025`).

**Things it is NOT:**
- ❌ SaaS-landing-page hero copy ("Transform your workflow")
- ❌ Corporate-safe hedging ("Designed to help you...")
- ❌ Medium-clone reading-time-first ("5 min read · 💡 Productivity")
- ❌ Emoji in body copy (see Iconography below)
- ❌ AI-slop maximalism (overwrought gradients + glass + "Powered by AI")

**Specific examples from source:**
- ✅ "It is not a blog. It is not a to-do app. It is not an LLM wrapper with a database behind it."
- ✅ "The AI doesn't remember that you mentioned a project last week. It reads the project's current status..."
- ✅ "auto-carryover is convenient, but it silently erodes your relationship with your own commitments."
- ✅ Content-type labels are plain: `article`, `essay`, `build-log`, `til`, `note`, `bookmark`, `digest`. Lowercase, hyphenated, no icons mandatory.

---

## Visual foundations

### Motif: the hexagon shell
The Koopa logo is a turtle with a **hexagon shell and antenna**. Hexagons are the one ornamental element that carries brand without looking like generic geometry. Use them: as empty states, as the tile shape behind status badges, as section dividers (hexagon + hairline), as the fallback avatar. Never as decorative hero background — the brief is allergic to that.

### Color
**Dark first.** Backgrounds run cool (`zinc`, oklch near neutral, slight blue bias). Accent is a single **cyan-teal** pulled straight from the logo — used surgically for links, active states, and the one "now" indicator. Semantic colors (success/warn/error/info) are muted — they never out-shout the accent.

- **Surfaces:** 4 elevation tokens — `bg`, `panel`, `elevated`, `overlay`. All within oklch lightness 0.14 – 0.20 in dark mode.
- **Text:** 4 tiers — `fg`, `fg-muted`, `fg-subtle`, `fg-faint`. High contrast at top; `fg-faint` is for timestamps and supporting metadata only.
- **Accent:** `oklch(0.72 0.10 210)` at full strength; paired with a `/10` tint for backgrounds and a slightly darker hover.
- **Light mode:** Mirror. Paper warm-white `oklch(0.985 0.005 90)` (not pure white — too clinical). Inks stay cool.

### Typography
- **Display:** `Space Grotesk` — headings, numerals, tight tracking, lets the admin feel precise and the public feel modern-but-not-generic.
- **Body:** `Inter` for UI, `IBM Plex Serif` for long-form article prose. Swapping in a serif for article bodies is the single biggest signal that reading is respected here.
- **Mono:** `JetBrains Mono` — code, terminals, IDs, shortcuts, timestamps where precision matters.
- **Scale** (modular, 1.2 minor-third for UI, 1.25 major-third for editorial):
  - UI: 11 / 12 / 13 / 14 / 16 / 18
  - Editorial: 14 / 16 / 17 / 20 / 24 / 30 / 38 / 48
- **Measure:** article body max-width 680px. Admin tables unbounded; admin prose 640px.

### Spacing, radii, shadows
- **Spacing scale:** 2 / 4 / 6 / 8 / 12 / 16 / 20 / 24 / 32 / 40 / 56 / 80. The low end (2–8) serves dense tables; the high end (40–80) serves reading pages. One scale, two usage patterns.
- **Radii:** small `2px` (inputs, chips, small buttons), medium `6px` (cards, panels), large `12px` (dialogs, hero blocks). **No pill buttons.** Never `rounded-full` except on avatars. The brief specifically excludes the "rounded-xl everywhere" SaaS look.
- **Borders:** 1px hairlines, `fg-faint` alpha. Cards mostly rely on border + background, not shadow.
- **Shadows:** only two levels. `shadow-1` for menus/dropdowns, `shadow-2` for dialogs/toasts. Both use true-black with low alpha in dark mode, cool-gray in light. No "glowy" or colored shadows.

### Backgrounds & texture
- **Grain overlay:** A faint (opacity `0.03`) noise SVG is composited on top of the app globally. This is lifted directly from the source — it's the single thing that keeps the UI from reading as clinical. Keep it.
- **No gradients** in fills. No glassmorphism. No full-bleed photo heroes. No illustrations. The product doesn't ship marketing imagery — it ships ideas.
- **Monochrome imagery** only where imagery is unavoidable (Uses page, Projects). Photos are desaturated and warmly tinted.

### Motion
Restrained. Explicit list:
- **Route transitions:** 100ms fade-out / 150ms fade-in, content-area only (lifted from source).
- **Menus / popovers:** 120ms slide-down, ease-out.
- **Hover:** color-only, 120ms ease. No scale, no lift.
- **Press:** 60ms, background goes one surface-step deeper. No scale.
- **Toasts:** 200ms slide-in from top.
- **Nothing bounces.** Cubic-bezier is `(0.2, 0, 0, 1)` or linear for opacity-only.
- **Reduced-motion:** all durations collapse to 0.01ms per the source CSS.

### Hover / press / focus states
- **Hover:** subtle background tint (`fg/5` in dark, `fg/8` in light) OR text color shift from `fg-muted` to `fg`. Never both.
- **Press:** one surface-step deeper background, no transform.
- **Focus:** visible 2px outline, `zinc-400` / `zinc-600` respectively. Global rule, zero-specificity. **Critical** — this exists in the source CSS and must be preserved.
- **Disabled:** 40% opacity, `cursor-not-allowed`.

### Transparency & blur
- **Header backdrop:** `bg-zinc-950/80` + `backdrop-blur-md`. Only place blur is used.
- **Overlays:** solid panels with borders. Modals dim with `black/60` scrim, no blur.
- **Never** rely on transparency for hierarchy — borders and backgrounds do that.

### Layout rules
- Max content width 1280px (`max-w-7xl` in source). Admin uses full viewport.
- Sticky header with `backdrop-blur`. Footer hairline-separated.
- Content padding: 16px mobile, 24px tablet, 32px desktop.
- Tables prefer 32px row-height in admin, 44px in admin-spacious.
- Focus ring is global — never stripped.

---

## Iconography

- **Primary icon set: [Lucide](https://lucide.dev/).** The source uses `lucide-icon` components everywhere; stroke-1.5, 18–20px default. This is loaded via CDN for prototypes (`https://unpkg.com/lucide@latest`).
- **Stroke weight:** 1.5px consistent. Never filled icons.
- **Sizing:** 14 (inline/dropdown chevrons), 16 (buttons), 18 (toolbar/nav), 20 (mobile), 24 (empty states).
- **Color:** inherits `currentColor`; always matches the surrounding text tier.
- **Social / brand icons:** X (Twitter) is the one exception — source ships an inline SVG path. GitHub + LinkedIn + Mail use Lucide.
- **No emoji in UI copy.** The source never uses them in product surfaces.
- **No unicode glyphs** as icons (no `→`, `✓`, `★` as functional affordance — always a real icon).
- **Fallback glyph:** the hexagon silhouette from the koopa mark, used for avatars and empty-state illustrations.
- **No custom illustration** shipped with this system. Where a figure is needed, use a real photograph (desaturated) or a placeholder hexagon. If a future illustration system is commissioned, it should match the stroke-1.5 line weight.

Icon assets are referenced from CDN in the preview cards; they are not copied as individual SVGs.

---

## Index

| File | What it is |
|---|---|
| `README.md` | You are here. Brand context, tone, foundations. |
| `SKILL.md` | Portable agent-skill frontmatter for downloading this system into Claude Code. |
| `colors_and_type.css` | CSS variables for every token (color, type, spacing, radii, shadow, motion). Base + semantic. |
| `assets/` | Logo variants, favicon, hero mark, grain overlay SVG. |
| `preview/` | Atomic design-system cards rendered as small HTMLs, surfaced in the Design System tab. |
| `ui_kits/public-site/` | Angular-style recreation of the visitor-facing site (Home, Article, Topic, Search). |
| `ui_kits/admin/` | Dense admin CMS recreation (Content list, Content editor, Pipeline, Learning dashboard). |

Each UI kit has its own `README.md`, `index.html` entry, and per-component `.jsx` files — see the kit folders.
