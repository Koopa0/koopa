# admin-v2 — Operator console

Status: shipped (Phase 1)
Last updated: 2026-04-14

The admin section at `/admin` is an operator console for koopa0.dev — a single-user, AI-native situational-awareness surface, **not** a CRUD admin panel. All mutations to the underlying data live in MCP tools and are executed by Claude. The frontend is read-only.

This doc is the developer reference for what the admin shell looks like, how the moving parts fit together, and how to extend it.

---

## 1. Mental model

```
┌─ Status Ribbon ─────────────────────────────────────────────┐
│ ◉ koopa0 admin · ● pipeline ok · ● feeds 100% · ● ai 34%   │  40 px, polled
├──────┬─────────────────────────────────────┬────────────────┤
│  N   │                                     │                │
│      │      Primary Surface                │   Inspector    │
│  A   │   (NowPage or AtlasPage)            │   panel        │
│      │                                     │   (slides in)  │
└──────┴─────────────────────────────────────┴────────────────┘
            56 px               grow                   480 px
```

- **Two modes** (`/admin/now`, `/admin/atlas`) replace the previous 6-group sidebar.
- **Inspector** is a cross-cutting right panel mounted at shell level. Any goal or project click anywhere in the admin opens it in place.
- **Status ribbon** runs across the top, polls `/api/admin/system/health` every 30 s while the tab is visible, derives three traffic-light tokens.
- The `/admin` index redirects to `/admin/now`.

---

## 2. Routes

```
/admin                                   → AdminLayoutComponent
  /admin                                 → redirect /admin/now
  /admin/now                             → NowPageComponent
  /admin/atlas                           → AtlasPageComponent
  /admin/oauth-callback                  → OAuthCallbackComponent (auth)
```

That's it. The legacy 17 admin routes (overview, activity/*, learn/*, content/*, system, commitments/*) were absorbed into NOW + ATLAS in Phase 1 Day 12 and deleted.

---

## 3. URL contract

The Inspector is driven by a query parameter that any link in the admin can produce:

```
/admin/now?inspect=goal:abc-123
/admin/atlas?inspect=project:xyz-789
```

- `InspectorService` is the single source of truth for the open entity.
- `AdminLayoutComponent` subscribes to `ActivatedRoute.queryParamMap` and forwards changes to `inspectorService.syncFromUrl(...)`.
- Opening from code: `inspector.open({ type: 'goal', id })` writes the URL via the Router; the layout effect then propagates it back into the signal. URL is the source of truth so share-links and back-button behavior stay consistent.

To open the inspector from a list row, prefer the declarative pattern:

```html
<a
  [routerLink]="[]"
  [queryParams]="{ inspect: 'goal:' + g.id }"
  queryParamsHandling="merge"
>
  ...
</a>
```

Plain click navigates and opens the panel. Middle-click opens the URL in a new tab and the panel auto-opens there too because the URL effect runs on hydration.

---

## 4. Keyboard contract

| Key   | Where        | Effect                                         |
|-------|--------------|------------------------------------------------|
| `⌘/`  | Anywhere     | Toggle the command palette (search + nav)     |
| `1`   | Inside admin | Switch to NOW mode                             |
| `2`   | Inside admin | Switch to ATLAS mode                           |
| `Esc` | Inspector open | Close the inspector                          |
| `j`   | Public site  | Scroll page down                               |
| `k`   | Public site  | Scroll page up                                 |
| `Shift+G` | Anywhere | Scroll to bottom                               |
| `Shift+A` | Anywhere | Jump to /admin                                 |

WCAG 2.1.4 compliance: the bottom of the admin left rail has an Accessibility toggle button. When enabled (persisted in `localStorage["koopa:a11y-mode"]`), every plain single-character shortcut is suppressed. Modifier-bearing shortcuts (`⌘/`, `Shift+A`, `Shift+G`) bypass the gate.

The keyboard handler is `KeyboardShortcutsService` (`core/services/keyboard-shortcuts.service.ts`), initialized once in `app.ts` via `afterNextRender(() => keyboardShortcuts.init())`.

Mode-change announcements are written to a global `<div id="koopa-announcer" role="status" aria-live="polite">` mounted in `app.html`. We do not depend on `@angular/cdk/a11y` to keep the initial bundle lean.

---

## 5. Inspector pattern

The Inspector is the only detail surface in the admin. There are no `/admin/.../:id` detail routes anymore.

```
admin/inspector/
├── inspector.types.ts                     InspectorTarget union
├── inspector.service.ts                   target signal + open/close + URL sync
├── inspector-panel.component.{ts,html}    Shell + 2 tabs + ARIA tablist
└── renderers/
    ├── goal-inspector/                    Goal renderer (PlanService.getGoalDetail)
    └── project-inspector/                 Project renderer (PlanService.getProjectDetail)
```

`InspectorService` is `providedIn: 'root'`, holds a target signal `{type, id} | null`, exposes `open(target)`, `close()`, and `syncFromUrl(rawValue)`. It does NOT hold the entity data — each renderer fetches its own via the appropriate service using `rxResource`.

`InspectorPanelComponent` is mounted in `admin-layout.html` as a sibling of the `<router-outlet>` so it survives mode switches. Inside it:

```html
@switch (target().type) {
  @case ('goal') { <app-goal-inspector [id]="target().id" [activeTab]="activeTab()"/> }
  @case ('project') { <app-project-inspector [id]="target().id" [activeTab]="activeTab()"/> }
}
```

Static `@switch` (not `@defer`) avoids a flash when the user moves between two entities of the same type.

### How to add a new entity type to the Inspector

1. Extend `InspectorTarget` in `inspector.types.ts`:
   ```ts
   export type InspectorTarget =
     | { type: 'goal'; id: string }
     | { type: 'project'; id: string }
     | { type: 'task'; id: string };
   ```
2. Update `InspectorService.parseTarget()` to accept the new type.
3. Create `admin/inspector/renderers/<type>-inspector/` with:
   - `<type>-inspector.component.ts` — `id` and `activeTab` inputs, `rxResource` data fetch
   - `.html` — Overview and Activity tab content
   - `.spec.ts` — at minimum: render title, render activity tab, render error state
4. Register in `inspector-panel.component.ts` imports and the `@switch` block.
5. Add a list-row link in any list page that should open the new type:
   ```html
   <a
     [routerLink]="[]"
     [queryParams]="{ inspect: 'task:' + task.id }"
     queryParamsHandling="merge"
   >
   ```

That's the entire surface. No new routes, no new endpoints (renderers reuse existing typed endpoints), no new shared types.

---

## 6. Status ribbon

`RibbonService` (`core/services/ribbon.service.ts`) wraps `SystemService.getHealth()` in an `rxResource` keyed by a tick signal. The tick increments every 30 s while the tab is visible (Page Visibility API). Hidden tabs cost zero requests; on visibility change back to visible the ribbon refreshes immediately.

Pure derivation helpers `derivePipeline`, `deriveFeeds`, `deriveBudget` produce three traffic-light tokens (`{label, status: 'ok' | 'warn' | 'error'}`) from the `SystemHealth` response. They are exported as module-level functions so unit tests can hit the logic without dancing around resource subscription scheduling.

`StatusRibbonComponent` (`admin/admin-layout/status-ribbon.component.ts`) renders the three tokens with status-tinted dots and text. It is mounted at the top of `admin-layout.html`.

---

## 7. NOW mode

`NowPageComponent` (`admin/now/now-page.component.ts`) renders a 12-column grid:

| Column       | Cols | Sources                                                  |
|--------------|------|----------------------------------------------------------|
| Attention    | 3    | `MyDayContext.needs_attention` + `yesterday_unfinished` + `overdue_tasks` |
| Today Stream | 6    | `today_plan` + `goal_pulse` (clickable to inspector)     |
| Ambient      | 3    | `DashboardTrends.execution / plan_adherence / goal_health / learning / content` |

Both `TodayService.getMyDayContext()` and `DashboardService.getDashboardTrends()` load in a single `forkJoin` on init.

The unified ranked Attention Queue is Phase 2 work — Phase 1 ships a count summary and a placeholder note.

---

## 8. ATLAS mode

`AtlasPageComponent` (`admin/atlas/atlas-page.component.ts`) — left facet rail (Type: Goal / Project) and a search list. Loads everything once via `forkJoin(getGoalsOverview, getProjectsOverview)`, flattens into `AtlasItem[]`, and pre-computes a lowercase `searchHaystack` for the per-keystroke filter.

Each row is a routerLink with `[queryParams]={inspect:type:id}`.

Phase 2 will extend the type set (concept, content, directive, report) once the corresponding inspector renderers ship.

---

## 9. Command palette

`CommandPaletteService` (`shared/command-palette/command-palette.service.ts`) lazily loads goals and projects on first open and surfaces them as fuzzy-searchable actions. Selecting a goal/project navigates to `/admin/atlas` with the inspect query param.

Trigger: `⌘/` (remapped from `⌘K` to avoid macOS Chrome's address-bar shortcut).

---

## 10. File structure (admin-v2 surfaces only)

```
src/app/admin/
├── admin-layout/
│   ├── admin-layout.{ts,html,spec.ts}      Shell — left rail + ribbon mount + outlet + inspector mount
│   └── status-ribbon.component.{ts,html,spec.ts}
├── inspector/
│   ├── inspector.types.ts
│   ├── inspector.service.ts (+ spec)
│   ├── inspector-panel.component.{ts,html,spec.ts}
│   └── renderers/
│       ├── goal-inspector/
│       └── project-inspector/
├── now/
│   └── now-page.component.{ts,html,spec.ts}
├── atlas/
│   └── atlas-page.component.{ts,html,spec.ts}
└── oauth-callback/
    └── (existing OAuth handler — outside admin-v2 scope)

src/app/core/services/
├── ribbon.service.{ts,spec.ts}            Polls system health, derives tokens
├── today.service.ts                        Used by NOW
├── dashboard.service.ts                    Used by NOW
├── plan.service.ts                         Used by ATLAS + inspector renderers
├── system.service.ts                       Used by RibbonService
└── keyboard-shortcuts.service.{ts,spec.ts}
```

---

## 11. What was not built

Anything not in the above structure was deliberately **not** built in Phase 1:

- ❌ Feature flag system — single-user frontend, `git revert` is rollback
- ❌ Inline edit of any entity — read-only doctrine (`internal/admin/admin.go`, `docs/ADMIN-API-REQUIREMENTS.md` Section A)
- ❌ `admin_ui` MCP participant
- ❌ `/api/admin/write/*` proxy
- ❌ Claude Inbox proposal table / endpoints / UI tray
- ❌ Polymorphic `/api/admin/inspect/:type/:id` endpoint
- ❌ Inspector for task / concept / content / directive / report / plan / session / journal / insight
- ❌ Inspector 4-tab structure (only Overview + Activity baseline)
- ❌ CHRONICLE mode (time scrubber, sparkline heatmap, event timeline)
- ❌ Atlas graph view (cytoscape / d3-force)
- ❌ Atlas full facet set (area, status, participant, deadline, staleness, domain)
- ❌ `/api/admin/now/attention` unified attention queue
- ❌ `/api/admin/now/stream` bundled endpoint
- ❌ Status ribbon drawers
- ❌ Keyboard cheatsheet overlay (`?` key)
- ❌ Virtual scroll
- ❌ `prefers-reduced-motion` polish
- ❌ Density toggle (comfort / compact)

All of these are Phase 2+ work. The Phase 1 north star was: read-heavy operator console, intent-oriented IA, single inspector pattern, no backward-compat ceremony.
