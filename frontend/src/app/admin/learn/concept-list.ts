import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, Brain } from 'lucide-angular';

@Component({
  selector: 'app-concept-list',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    <div class="mx-auto max-w-3xl px-4 py-6 sm:px-6">
      <div class="mb-6">
        <h1 class="text-lg font-semibold text-zinc-100">Concepts</h1>
        <p class="text-sm text-zinc-500">
          Learning concept browser and mastery tracking
        </p>
      </div>
      <div
        class="rounded-sm border border-dashed border-zinc-800 px-6 py-12 text-center"
      >
        <lucide-icon
          [img]="BrainIcon"
          [size]="32"
          class="mx-auto mb-3 text-zinc-700"
          aria-hidden="true"
        />
        <p class="text-sm text-zinc-500 mb-1">
          Concept list under construction
        </p>
        <p class="text-xs text-zinc-600">
          Access individual concepts from the
          <a
            routerLink="/admin/learn/dashboard"
            class="text-zinc-400 underline hover:text-zinc-300"
            >Learning Dashboard</a
          >
          weakness analysis
        </p>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ConceptListComponent {
  protected readonly BrainIcon = Brain;
}
