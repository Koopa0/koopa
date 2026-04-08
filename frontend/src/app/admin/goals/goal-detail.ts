import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-goal-detail',
  standalone: true,
  imports: [RouterLink],
  template: `
    <div class="mx-auto max-w-3xl px-4 py-6 sm:px-6">
      <a
        routerLink="/admin/plan/goals"
        class="mb-4 inline-flex items-center text-sm text-zinc-500 no-underline hover:text-zinc-300"
      >
        ← Goals
      </a>
      <div
        class="rounded-sm border border-dashed border-zinc-800 px-6 py-12 text-center"
      >
        <p class="text-zinc-500">Goal Detail — 建設中</p>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GoalDetailComponent {}
