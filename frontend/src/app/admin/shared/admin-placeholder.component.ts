import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  effect,
  inject,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute } from '@angular/router';
import { map } from 'rxjs';
import { AdminTopbarService } from '../admin-layout/admin-topbar.service';

interface PlaceholderVm {
  title: string;
  crumbs: string[];
}

const EMPTY_VM: PlaceholderVm = { title: '', crumbs: [] };

/**
 * Reusable stub page for admin routes that have a nav entry in the
 * Mission Control v2 IA but whose full implementation ships in a later
 * pass. Reads `{ title, crumbs }` from the route `data` config and
 * publishes them to the topbar.
 *
 * Remove a route's mapping to this component once the real page exists.
 */
@Component({
  selector: 'app-admin-placeholder',
  standalone: true,
  template: `
    <section
      class="flex flex-1 flex-col items-center justify-center p-8 text-center"
      data-testid="admin-placeholder"
    >
      <p class="mb-2 font-mono text-xs uppercase tracking-wider text-zinc-500">
        Coming soon
      </p>
      <h2 class="mb-3 font-display text-xl font-semibold text-zinc-100">
        {{ vm().title }}
      </h2>
      <p class="max-w-md text-sm text-zinc-400">
        This surface is part of Mission Control Admin v2. The route exists so
        navigation and keyboard shortcuts resolve; the page itself will land in
        a follow-up task.
      </p>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class AdminPlaceholderComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly vm = toSignal(
    this.route.data.pipe(
      map(
        (data): PlaceholderVm => ({
          title: (data['title'] as string) ?? 'Admin',
          crumbs: (data['crumbs'] as string[]) ?? [],
        }),
      ),
    ),
    { initialValue: EMPTY_VM },
  );

  constructor() {
    effect(() => this.topbar.set(this.vm()));
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }
}
