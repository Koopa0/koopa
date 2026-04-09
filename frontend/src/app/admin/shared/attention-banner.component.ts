import {
  Component,
  ChangeDetectionStrategy,
  input,
  output,
  computed,
} from '@angular/core';
import {
  LucideAngularModule,
  AlertTriangle,
  AlertCircle,
  Info,
  X,
} from 'lucide-angular';

const SEVERITY_CONFIG = {
  warning: {
    bg: 'bg-amber-900/30 border-amber-700/50',
    icon: 'text-amber-400',
    text: 'text-amber-200',
  },
  error: {
    bg: 'bg-red-900/30 border-red-700/50',
    icon: 'text-red-400',
    text: 'text-red-200',
  },
  info: {
    bg: 'bg-sky-900/30 border-sky-700/50',
    icon: 'text-sky-400',
    text: 'text-sky-200',
  },
} as const;

@Component({
  selector: 'app-attention-banner',
  standalone: true,
  imports: [LucideAngularModule],
  template: `
    <div
      class="flex w-full items-center gap-3 rounded-sm border px-4 py-3"
      [class]="config().bg"
      role="alert"
    >
      <lucide-icon
        [img]="icon()"
        [size]="18"
        class="shrink-0"
        [class]="config().icon"
      />
      <div class="min-w-0 flex-1 text-sm" [class]="config().text">
        <ng-content />
      </div>
      <button
        type="button"
        class="shrink-0 rounded-xs p-1 text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
        (click)="dismissed.emit()"
        aria-label="Close"
      >
        <lucide-icon [img]="XIcon" [size]="14" />
      </button>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AttentionBannerComponent {
  readonly severity = input<'warning' | 'error' | 'info'>('warning');
  readonly dismissed = output<void>();

  protected readonly XIcon = X;

  protected readonly config = computed(() => SEVERITY_CONFIG[this.severity()]);

  protected readonly icon = computed(() => {
    switch (this.severity()) {
      case 'error':
        return AlertCircle;
      case 'info':
        return Info;
      default:
        return AlertTriangle;
    }
  });
}
