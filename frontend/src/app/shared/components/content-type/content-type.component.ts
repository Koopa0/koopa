import {
  Component,
  ChangeDetectionStrategy,
  input,
  computed,
} from '@angular/core';

/** koopa0.dev content-type taxonomy (pack). The live, published surface. */
export type ContentType =
  | 'article'
  | 'essay'
  | 'build-log'
  | 'til'
  | 'digest';

/**
 * DS koopa pack — content-type label (`ui-type`): a categorical dot + the
 * lowercase, hyphenated type name. Colors come from the `--dot-*` tokens in
 * styles.css. Voice rule: type labels are plain, lowercase, no icons.
 */
@Component({
  selector: 'app-content-type',
  template: `
    <span
      class="inline-flex items-center gap-1.5 font-mono text-[11px] tracking-[0.03em] text-fg-muted"
      [attr.data-testid]="'content-type-' + type()"
    >
      <span
        class="size-[7px] shrink-0 rounded-full"
        [style.background-color]="dotColor()"
        aria-hidden="true"
      ></span>
      {{ type() }}
    </span>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ContentTypeComponent {
  readonly type = input.required<ContentType>();

  protected readonly dotColor = computed(
    () => `var(--dot-${this.type()}, var(--fg-faint))`,
  );
}
