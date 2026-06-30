import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Hexagon, LucideAngularModule } from 'lucide-angular';
import type { TodoHistoryEntry } from '../../../core/services/todo.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { EmptyStateComponent } from '../../../shared/components/empty-state/empty-state.component';
import { GtdRowComponent } from './gtd-row.component';
import { ClarifyModalComponent } from './clarify-modal.component';
import { RecurrenceModalComponent } from './recurrence-modal.component';
import { TodoDetailModalComponent } from './todo-detail-modal.component';
import { GtdStore } from './gtd.store';
import {
  GTD_TABS,
  initialViewOf,
  isInteractiveTarget,
  isTriageable,
  keyActionFor,
  resolvedKindOf,
  viewLabel,
  type ResolvedKind,
} from './gtd-view';

/**
 * Todos — the status-flow surface over the todo backlog: Pending, In Progress,
 * Someday, and Complete (the resolved history) as segmented tabs, with j/k +
 * verb keyboard triage and the clarify / recurrence dialogs. Inbox is its own
 * page (InboxPageComponent); capture happens there. The initial tab comes from
 * route data, defaulting to Pending. State and mutations live in the
 * page-provided {@link GtdStore}.
 */
@Component({
  selector: 'app-gtd-page',
  imports: [
    DatePipe,
    LucideAngularModule,
    EmptyStateComponent,
    GtdRowComponent,
    ClarifyModalComponent,
    RecurrenceModalComponent,
    TodoDetailModalComponent,
  ],
  providers: [GtdStore],
  templateUrl: './gtd.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class GtdPageComponent {
  protected readonly store = inject(GtdStore);
  private readonly topbar = inject(AdminTopbarService);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly HexagonIcon = Hexagon;
  protected readonly tabs = GTD_TABS;

  protected readonly showSelection = computed(() =>
    isTriageable(this.store.view()),
  );

  constructor() {
    this.store.setView(initialViewOf(this.route.snapshot.data['gtdView']));
    effect(() => {
      this.topbar.set({
        title: 'Todos',
        crumbs: ['Daily', viewLabel(this.store.view())],
      });
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected readInput(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  /** Resolution kind for a Complete-tab row, from its current state. */
  protected resolvedKind(state: TodoHistoryEntry['state']): ResolvedKind {
    return resolvedKindOf(state);
  }

  protected handleKeydown(event: KeyboardEvent): void {
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey)
      return;
    if (this.store.clarifyTarget() !== null) return;
    if (this.store.recurrenceTarget() !== null) return;
    if (this.store.detailTarget() !== null) return;
    if (isInteractiveTarget(event.target)) return;
    const view = this.store.view();
    if (!isTriageable(view)) return;
    const rows = this.store.rows();
    if (rows.length === 0) return;
    const action = keyActionFor(event.key, view);
    if (!action) return;
    event.preventDefault();
    const index = this.store.selection();
    const row = rows[index];
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
      case 'defer':
        this.store.deferRow(row);
        break;
      case 'drop':
        this.store.dropRow(row);
        break;
      case 'pull':
        this.store.pullRow(row);
        break;
      case 'recurrence':
        this.store.openRecurrence(row);
        break;
      default:
        break;
    }
  }
}
