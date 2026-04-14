import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
} from '@angular/core';
import {
  RibbonService,
  type RibbonStatus,
} from '../../core/services/ribbon.service';

/**
 * Top-of-shell status ribbon. Renders three traffic-light tokens
 * (pipeline, feeds, AI budget) sourced from {@link RibbonService}.
 * Mounted inside {@link AdminLayoutComponent} as the first row of the
 * vertical flex column.
 */
@Component({
  selector: 'app-status-ribbon',
  standalone: true,
  templateUrl: './status-ribbon.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StatusRibbonComponent {
  private readonly ribbon = inject(RibbonService);

  protected readonly tokens = this.ribbon.tokens;
  protected readonly isLoading = this.ribbon.isLoading;
  protected readonly hasError = this.ribbon.hasError;

  protected readonly hasTokens = computed(() => this.tokens() !== null);

  protected dotClass(status: RibbonStatus): string {
    switch (status) {
      case 'ok':
        return 'bg-emerald-500';
      case 'warn':
        return 'bg-amber-400';
      case 'error':
        return 'bg-red-500';
    }
  }

  protected textClass(status: RibbonStatus): string {
    switch (status) {
      case 'ok':
        return 'text-zinc-400';
      case 'warn':
        return 'text-amber-300';
      case 'error':
        return 'text-red-400';
    }
  }
}
