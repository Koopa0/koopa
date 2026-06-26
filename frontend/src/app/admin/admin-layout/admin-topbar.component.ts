import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  signal,
} from '@angular/core';
import { LucideAngularModule, Menu, MoreHorizontal, Search } from 'lucide-angular';
import { AdminTopbarService, type TopbarAction } from './admin-topbar.service';
import { CommandPaletteService } from '../../shared/command-palette/command-palette.service';

type ActionKind = NonNullable<TopbarAction['kind']>;

const ACTION_CLASS_MAP: Record<ActionKind, string> = {
  primary:
    'border-brand bg-brand font-semibold text-[oklch(0.12_0.02_260)] hover:bg-brand-strong',
  secondary: 'border-border bg-elevated text-fg-muted hover:bg-overlay hover:text-fg',
  destructive: 'border-transparent text-error hover:bg-error-bg',
};

/**
 * Topbar renders the page title, optional crumbs, the global ⌘K search
 * launcher, and page-specific action chips coming from
 * {@link AdminTopbarService}. The topbar itself is stateless — it reads
 * the service signal and dispatches to action handlers owned by the
 * host page. Overflow actions surface inside a click-to-open `…` menu.
 *
 * Height: 44px.
 */
@Component({
  selector: 'app-admin-topbar',
  imports: [LucideAngularModule],
  templateUrl: './admin-topbar.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class:
      'flex h-11 shrink-0 items-center gap-4 border-b border-border bg-panel px-5',
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

  protected readonly drawerOpen = this.topbar.drawerOpen;

  protected readonly SearchIcon = Search;
  protected readonly OverflowIcon = MoreHorizontal;
  protected readonly MenuIcon = Menu;

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

  protected toggleDrawer(): void {
    this.topbar.toggleDrawer();
  }

  protected openSearch(): void {
    this.palette.open();
  }
}
