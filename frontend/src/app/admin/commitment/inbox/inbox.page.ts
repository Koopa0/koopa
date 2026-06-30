import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  inject,
  signal,
  viewChildren,
} from '@angular/core';
import { Hexagon, LucideAngularModule, Plus } from 'lucide-angular';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { EmptyStateComponent } from '../../../shared/components/empty-state/empty-state.component';
import { GtdRowComponent } from '../todos/gtd-row.component';
import { ClarifyModalComponent } from '../todos/clarify-modal.component';
import { GtdStore } from '../todos/gtd.store';
import {
  isInteractiveTarget,
  keyActionFor,
  type GtdView,
} from '../todos/gtd-view';

/**
 * Inbox — the capture + triage surface over the unclarified backlog. A
 * persistent capture bar drops raw thoughts into the inbox; the list
 * below is the inbox rows with j/k + verb keyboard triage and the
 * clarify dialog. Reuses the GTD backlog store, row, and clarify modal,
 * locked to the inbox view (no tabs). State and mutations live in the
 * page-provided {@link GtdStore}, so they die with the route.
 */
@Component({
  selector: 'app-inbox-page',
  imports: [
    LucideAngularModule,
    EmptyStateComponent,
    GtdRowComponent,
    ClarifyModalComponent,
  ],
  providers: [GtdStore],
  templateUrl: './inbox.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class InboxPageComponent {
  protected readonly store = inject(GtdStore);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly HexagonIcon = Hexagon;
  protected readonly PlusIcon = Plus;
  protected readonly view: GtdView = 'inbox';
  protected readonly captureDraft = signal('');

  private readonly gtdRows = viewChildren(GtdRowComponent);

  constructor() {
    this.store.setView('inbox');
    this.topbar.set({ title: 'Inbox', crumbs: ['Daily', 'Inbox'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected readInput(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected submitCapture(): void {
    const title = this.captureDraft().trim();
    if (!title) return;
    this.store.capture(title, () => this.captureDraft.set(''));
  }

  protected handleKeydown(event: KeyboardEvent): void {
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey)
      return;
    if (this.store.clarifyTarget() !== null) return;
    if (isInteractiveTarget(event.target)) return;
    const rows = this.store.rows();
    if (rows.length === 0) return;
    const action = keyActionFor(event.key, this.view);
    if (!action) return;
    event.preventDefault();
    const index = this.store.selection();
    const row = rows[index];
    // Inbox actions that open the clarify dialog: focus the row's trigger
    // first so the modal's focus trap restores focus to it on close.
    if (action === 'advance' || action === 'clarify' || action === 'pull') {
      this.gtdRows()[index]?.focusOpen();
    }
    switch (action) {
      case 'down':
        this.store.selectedIndex.set(Math.min(index + 1, rows.length - 1));
        break;
      case 'up':
        this.store.selectedIndex.set(Math.max(index - 1, 0));
        break;
      case 'advance':
        this.store.advanceRow(row);
        break;
      case 'clarify':
        // Go through openClarify (not a raw clarifyTarget.set) so the clarify
        // intent is reset — a stale 'pull' intent from an earlier t must not
        // leak into a keyboard clarify and append the todo to today's plan.
        this.store.openClarify(row);
        break;
      case 'defer':
        this.store.deferRow(row);
        break;
      case 'drop':
        this.store.dropRow(row);
        break;
      case 'pull':
        this.store.pullRow(row);
        break;
      default:
        break;
    }
  }
}
