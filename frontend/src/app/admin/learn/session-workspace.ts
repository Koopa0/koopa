import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, ArrowLeft, FlaskConical } from 'lucide-angular';

@Component({
  selector: 'app-session-workspace',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    <div class="mx-auto max-w-3xl px-4 py-6 sm:px-6">
      <a
        routerLink="/admin/learn/dashboard"
        class="mb-6 inline-flex items-center gap-1.5 text-sm text-zinc-500 no-underline hover:text-zinc-300"
        data-testid="back-to-dashboard"
      >
        <lucide-icon [img]="ArrowLeftIcon" [size]="14" />
        Back to Learning Dashboard
      </a>

      <div
        class="mt-8 flex flex-col items-center justify-center rounded-sm border border-dashed border-zinc-800 px-6 py-16 text-center"
      >
        <lucide-icon
          [img]="FlaskConicalIcon"
          [size]="32"
          class="mb-4 text-zinc-600"
        />
        <h1 class="text-lg font-semibold text-zinc-300 mb-2">
          Session Workspace — Under Construction
        </h1>
        <p class="max-w-md text-sm text-zinc-500">
          The session workspace will support real-time recording of
          problem-solving attempts, tracking observations, and automatically
          generating learning summaries when the session ends.
        </p>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SessionWorkspaceComponent {
  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly FlaskConicalIcon = FlaskConical;
}
