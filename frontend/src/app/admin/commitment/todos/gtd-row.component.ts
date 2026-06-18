import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  output,
} from '@angular/core';
import {
  CalendarPlus,
  Inbox,
  LucideAngularModule,
  Moon,
  Rss,
  X,
} from 'lucide-angular';
import type { TodoRow } from '../../../core/services/todo.service';
import { EnergyMeterComponent } from '../../../shared/components/energy-meter/energy-meter.component';
import {
  advanceActionFor,
  ageLabel,
  dueChip,
  energyOf,
  recurLabel,
  type GtdView,
} from './gtd-view';

/**
 * One GTD list row. The inbox view renders the capture variant
 * (source icon, origin chip, age, Clarify/Defer/Drop); today, pending
 * and someday render the default variant (check control, meta chips,
 * Start/Complete plus the contextual ghost actions). Row actions are
 * hover/selection-revealed per the admin vocabulary.
 */
@Component({
  selector: 'app-gtd-row',
  imports: [LucideAngularModule, EnergyMeterComponent],
  templateUrl: './gtd-row.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    role: 'listitem',
    class:
      'group flex min-h-8 items-center gap-2.5 border-b border-border-faint px-5 py-1.5 transition-colors hover:bg-overlay',
    '[class.bg-brand-faint]': 'selected()',
    '[style.box-shadow]': 'selected() ? "inset 2px 0 0 var(--brand)" : null',
    '[attr.data-selected]': 'selected()',
    '(mouseenter)': 'rowHover.emit()',
  },
})
export class GtdRowComponent {
  readonly item = input.required<TodoRow>();
  readonly view = input.required<GtdView>();
  readonly selected = input(false);
  readonly busy = input(false);

  readonly rowHover = output<void>();
  readonly clarify = output<void>();
  readonly advance = output<void>();
  readonly deferRow = output<void>();
  readonly dropRow = output<void>();
  readonly pull = output<void>();

  protected readonly MoonIcon = Moon;
  protected readonly XIcon = X;
  protected readonly CalendarPlusIcon = CalendarPlus;

  private readonly todayIso = new Date().toISOString().slice(0, 10);

  // 'manual' when Koopa captured it in the admin UI ('human'); 'agent' for a
  // capture an agent dropped in via MCP — hermes (vault sweep / Telegram
  // bridge), planner, system, etc. all stamp their own identity, never
  // 'human'.
  protected readonly sourceKind = computed(() =>
    this.item().created_by === 'human' ? 'manual' : 'agent',
  );
  protected readonly sourceIcon = computed(() =>
    this.sourceKind() === 'manual' ? Inbox : Rss,
  );
  protected readonly age = computed(() => ageLabel(this.item().created_at));
  protected readonly energy = computed(() => energyOf(this.item().energy));
  protected readonly due = computed(() =>
    dueChip(this.item().due, this.todayIso),
  );
  protected readonly recur = computed(() =>
    recurLabel(this.item().recur_interval, this.item().recur_unit),
  );
  protected readonly inProgress = computed(
    () => this.item().state === 'in_progress',
  );
  protected readonly verbLabel = computed(() => {
    switch (advanceActionFor(this.item().state)) {
      case 'complete':
        return 'Complete';
      case 'activate':
        return 'Activate';
      default:
        return 'Start';
    }
  });
  protected readonly showPull = computed(
    () => this.view() === 'pending' || this.view() === 'someday',
  );
  protected readonly showDefer = computed(() => this.view() !== 'someday');
}
