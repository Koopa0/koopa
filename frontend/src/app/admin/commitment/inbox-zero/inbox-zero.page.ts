import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  signal,
} from '@angular/core';
import { Inbox, LucideAngularModule } from 'lucide-angular';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { EmptyStateComponent } from '../../../shared/components/empty-state/empty-state.component';
import { ClarifyModalComponent } from '../todos/clarify-modal.component';
import { ageLabel, isInteractiveTarget, type ClarifyResult } from '../todos/gtd-view';
import { InboxZeroStore } from './inbox-zero.store';

/** Footer key legend — the four triage decisions plus quit-to-todos. */
interface KeyHint {
  keys: string;
  label: string;
}

const KEY_LEGEND: readonly KeyHint[] = [
  { keys: 'c', label: 'clarify' },
  { keys: 't', label: 'today' },
  { keys: 'd', label: 'defer' },
  { keys: 'x', label: 'drop' },
];

/**
 * Inbox Zero — a focused, full-screen, one-card-at-a-time triage over the
 * GTD inbox. Each capture is shown large and centered with its source, age
 * and text; a single keystroke decides it (c clarify, t clarify-and-pull,
 * d defer, x drop) and the next card slides up. Built for the hermes /
 * Telegram capture flow where the inbox fills 10–20/day and the per-row
 * clarify modal would mean a window open/close per item. Reuses the GTD
 * advance plumbing and the clarify dialog wholesale; state lives in the
 * page-provided {@link InboxZeroStore}.
 */
@Component({
  selector: 'app-inbox-zero-page',
  standalone: true,
  imports: [LucideAngularModule, EmptyStateComponent, ClarifyModalComponent],
  providers: [InboxZeroStore],
  templateUrl: './inbox-zero.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class InboxZeroPageComponent {
  protected readonly store = inject(InboxZeroStore);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly InboxIcon = Inbox;
  protected readonly legend = KEY_LEGEND;
  protected readonly clarifyBusy = signal(false);

  // Source chip — system captures (hermes / Telegram bridge) read as a
  // feed; everything else is a manual capture.
  protected readonly source = computed(() =>
    this.store.current()?.created_by === 'system' ? 'feed' : 'capture',
  );
  protected readonly age = computed(() => {
    const row = this.store.current();
    return row ? ageLabel(row.created_at) : '';
  });

  constructor() {
    effect(() => {
      this.topbar.set({
        title: 'Inbox Zero',
        crumbs: ['Daily', 'Inbox Zero'],
      });
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected clarified(result: ClarifyResult): void {
    this.store.clarified(result);
  }

  protected handleKeydown(event: KeyboardEvent): void {
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey)
      return;
    // The clarify dialog owns every keystroke while it is open.
    if (this.store.clarifyRequest() !== null) return;
    if (isInteractiveTarget(event.target)) return;
    if (this.store.current() === null) return;
    switch (event.key) {
      case 'c':
        event.preventDefault();
        this.store.openClarify('clarify');
        break;
      case 't':
        event.preventDefault();
        this.store.openClarify('pull');
        break;
      case 'd':
        event.preventDefault();
        this.store.defer();
        break;
      case 'x':
        event.preventDefault();
        this.store.drop();
        break;
      default:
        break;
    }
  }
}
