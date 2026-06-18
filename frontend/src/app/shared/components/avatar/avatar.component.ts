import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

export type AvatarSize = 'sm' | 'md' | 'lg';
/** koopa pack — AI actor identities (admin surfaces). */
export type AvatarActor = 'human' | 'claude-cowork' | 'claude-code' | 'system';

const SIZE_CLASSES: Record<AvatarSize, string> = {
  sm: 'size-6 text-[10px]',
  md: 'size-8 text-xs',
  lg: 'size-11 text-base',
};

const ACTOR_COLORS: Record<AvatarActor, { bg: string; fg: string }> = {
  human: { bg: 'var(--brand-muted)', fg: 'var(--brand-strong)' },
  'claude-cowork': { bg: 'var(--info-bg)', fg: 'var(--info)' },
  'claude-code': {
    bg: 'color-mix(in oklab, var(--dot-essay) 18%, transparent)',
    fg: 'var(--dot-essay)',
  },
  system: { bg: 'var(--overlay)', fg: 'var(--fg-subtle)' },
};

/**
 * DS avatar — `ui-avatar`. Circular image with an initials fallback when
 * `src` is absent (or while it loads). Three sizes: 24 / 32 / 44px.
 */
@Component({
  selector: 'app-avatar',
  template: `
    <span
      [class]="classes()"
      [style.background-color]="actorColor()?.bg"
      [style.color]="actorColor()?.fg"
      [attr.data-testid]="testId()"
    >
      @if (src()) {
        <img
          [src]="src()"
          [alt]="alt()"
          class="size-full object-cover"
          decoding="async"
          loading="lazy"
        />
      } @else {
        <span aria-hidden="true">{{ initials() }}</span>
      }
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AvatarComponent {
  readonly src = input<string | null>(null);
  readonly alt = input('');
  readonly initials = input('');
  readonly size = input<AvatarSize>('md');
  readonly actor = input<AvatarActor | null>(null);
  readonly testId = input<string | null>(null);

  protected readonly actorColor = computed(() => {
    const a = this.actor();
    return a ? ACTOR_COLORS[a] : null;
  });

  protected readonly classes = computed(() =>
    [
      'inline-flex shrink-0 items-center justify-center overflow-hidden rounded-full',
      'bg-elevated font-display font-semibold text-fg-muted select-none',
      SIZE_CLASSES[this.size()],
    ].join(' '),
  );
}
