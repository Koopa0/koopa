import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  signal,
} from '@angular/core';
import { LucideAngularModule, MoreHorizontal, Search } from 'lucide-angular';
import { AdminTopbarService, type TopbarAction } from './admin-topbar.service';
import { CommandPaletteService } from '../../shared/command-palette/command-palette.service';

type ActionKind = NonNullable<TopbarAction['kind']>;

const ACTION_CLASS_MAP: Record<ActionKind, string> = {
  primary:
    'bg-sky-600 text-white hover:bg-sky-500 disabled:bg-sky-900/60 disabled:text-sky-300',
  secondary: 'text-zinc-300 hover:bg-zinc-800/80 disabled:text-zinc-600',
  destructive: 'text-red-300 hover:bg-red-950/50 disabled:text-red-800',
};

/**
 * Topbar renders the page title, optional crumbs, the global ⌘K search
 * launcher, and page-specific action chips coming from
 * {@link AdminTopbarService}. The topbar itself is stateless — it reads
 * the service signal and dispatches to action handlers owned by the
 * host page. Overflow actions surface inside a click-to-open `…` menu.
 *
 * Height: 48px.
 */
@Component({
  selector: 'app-admin-topbar',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './admin-topbar.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class:
      'flex h-12 shrink-0 items-center gap-3 border-b border-zinc-800 bg-zinc-950/80 px-4',
    role: 'toolbar',
    'aria-label': 'Admin topbar',
  },
})
export class AdminTopbarComponent {
  private readonly topbar = inject(AdminTopbarService);
  private readonly palette = inject(CommandPaletteService);

  protected readonly context = this.topbar.context;
  protected readonly actionClasses = computed(() => ACTION_CLASS_MAP);

  protected readonly hasOverflow = computed(
    () => (this.context().overflowActions ?? []).length > 0,
  );

  private readonly _overflowOpen = signal(false);
  protected readonly overflowOpen = this._overflowOpen.asReadonly();

  protected readonly SearchIcon = Search;
  protected readonly OverflowIcon = MoreHorizontal;

  protected runAction(action: TopbarAction): void {
    if (action.disabled) return;
    action.run();
    this._overflowOpen.set(false);
  }

  protected toggleOverflow(): void {
    this._overflowOpen.update((v) => !v);
  }

  protected closeOverflow(): void {
    this._overflowOpen.set(false);
  }

  protected openSearch(): void {
    this.palette.open();
  }
}
