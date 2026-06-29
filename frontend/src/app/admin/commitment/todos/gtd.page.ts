import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  viewChild,
  viewChildren,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DatePipe } from '@angular/common';
import { Hexagon, LucideAngularModule, Plus } from 'lucide-angular';
import type { TodoItem } from '../../../core/services/todo.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { EmptyStateComponent } from '../../../shared/components/empty-state/empty-state.component';
import { EnergyMeterComponent } from '../../../shared/components/energy-meter/energy-meter.component';
import { GtdRowComponent } from './gtd-row.component';
import { ClarifyModalComponent } from './clarify-modal.component';
import { RecurrenceModalComponent } from './recurrence-modal.component';
import { GtdStore } from './gtd.store';
import {
  GTD_TABS,
  dueChip,
  energyOf,
  initialViewOf,
  isInteractiveTarget,
  isTriageable,
  keyActionFor,
  recurLabel,
  viewLabel,
} from './gtd-view';

/**
 * GTD surface — six segmented views over the todo backlog (Inbox,
 * Today, Pending, Someday, Recurring, History) with a persistent
 * capture bar, j/k + verb keyboard triage, and the clarify dialog.
 * The initial view comes from route data so the Inbox and Todos nav
 * entries land on their own tab; each entry is a distinct route
 * config, so switching between them remounts and resets the view.
 * State and mutations live in the page-provided {@link GtdStore}.
 */
@Component({
  selector: 'app-gtd-page',
  imports: [
    DatePipe,
    LucideAngularModule,
    EmptyStateComponent,
    EnergyMeterComponent,
    GtdRowComponent,
    ClarifyModalComponent,
    RecurrenceModalComponent,
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
  protected readonly PlusIcon = Plus;
  protected readonly tabs = GTD_TABS;
  protected readonly captureDraft = signal('');

  private readonly todayIso = new Date().toISOString().slice(0, 10);
  private readonly captureInput =
    viewChild<ElementRef<HTMLInputElement>>('captureInput');
  private readonly gtdRows = viewChildren(GtdRowComponent);

  protected readonly showSelection = computed(() =>
    isTriageable(this.store.view()),
  );

  constructor() {
    this.store.setView(initialViewOf(this.route.snapshot.data['gtdView']));
    effect(() => {
      this.topbar.set({
        title: 'Todos',
        crumbs: ['Daily', viewLabel(this.store.view())],
        actions: [
          {
            id: 'gtd-capture-action',
            label: 'Capture',
            kind: 'primary',
            run: () => this.captureInput()?.nativeElement.focus(),
          },
        ],
      });
    });
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

  protected recurBadge(item: TodoItem): string | null {
    return recurLabel(item.recur_interval, item.recur_unit);
  }

  protected recurDue(item: TodoItem): ReturnType<typeof dueChip> {
    return dueChip(item.due, this.todayIso);
  }

  protected recurEnergy(item: TodoItem): ReturnType<typeof energyOf> {
    return energyOf(item.energy);
  }

  protected handleKeydown(event: KeyboardEvent): void {
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey)
      return;
    if (this.store.clarifyTarget() !== null) return;
    if (this.store.recurrenceTarget() !== null) return;
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
    // Inbox actions that open the clarify dialog: focus the row's trigger
    // first so the modal's focus trap restores focus to it on close.
    if (
      view === 'inbox' &&
      (action === 'advance' || action === 'clarify' || action === 'pull')
    ) {
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
        this.store.clarifyTarget.set(row);
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
