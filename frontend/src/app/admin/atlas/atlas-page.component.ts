import { ChangeDetectionStrategy, Component } from '@angular/core';

/**
 * ATLAS mode entry point. Phase 1 placeholder until Day 9-10 fills in
 * faceted search across goals, projects, and concepts. Renders an empty
 * state describing what is coming so the route is reachable from the
 * left rail without misrepresenting the implementation status.
 */
@Component({
  selector: 'app-atlas-page',
  standalone: true,
  template: `
    <div class="mx-auto max-w-3xl px-6 py-16 text-center">
      <div
        class="mb-3 font-mono text-xs uppercase tracking-wider text-zinc-500"
      >
        ATLAS
      </div>
      <h1 class="text-xl font-semibold text-zinc-200">Faceted entity search</h1>
      <p class="mt-3 text-sm text-zinc-400">
        Cross-entity search across goals, projects, and concepts. Filtering by
        type, area, status, and staleness. Selecting a row opens the Inspector.
      </p>
      <p class="mt-2 font-mono text-xs text-zinc-600">
        coming Day 9–10 of admin-v2
      </p>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AtlasPageComponent {}
