import {
  Component,
  ChangeDetectionStrategy,
  input,
  signal,
  inject,
} from '@angular/core';
import { Clipboard } from '@angular/cdk/clipboard';

const COPIED_RESET_MS = 2000;

/**
 * DS code block — `ui-code-block`. Framed mono panel: a header bar shows the
 * language tag and a copy button, the body renders the (non-highlighted) source
 * in a horizontally scrollable `<pre>`. Copy writes to the clipboard via the
 * CDK `Clipboard` service and flips the button to a transient "Copied" state
 * for ~2s.
 */
@Component({
  selector: 'app-code-block',
  template: `
    <div
      class="overflow-hidden rounded-md border border-border font-mono"
      [attr.data-testid]="testId()"
    >
      <div
        class="flex items-center justify-between border-b border-border bg-elevated px-3 py-[7px]"
      >
        <span class="text-[11px] text-fg-subtle">{{ lang() }}</span>
        <button
          type="button"
          class="inline-flex cursor-pointer items-center gap-1.5 border-none bg-transparent text-[11px] text-fg-subtle transition-colors duration-[120ms] hover:text-fg-muted [&_svg]:size-3.5"
          [attr.aria-label]="copied() ? 'Copied to clipboard' : 'Copy code'"
          [attr.data-testid]="testId() ? testId() + '-copy' : 'code-block-copy'"
          (click)="copy()"
        >
          @if (copied()) {
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <path d="M20 6L9 17l-5-5" />
            </svg>
            <span>Copied</span>
          } @else {
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <rect x="9" y="9" width="11" height="11" rx="2" />
              <path
                d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"
              />
            </svg>
            <span>Copy</span>
          }
        </button>
      </div>
      <pre
        class="overflow-x-auto p-4"
      ><code class="text-[13px] leading-relaxed text-fg-muted">{{ code() }}</code></pre>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CodeBlockComponent {
  readonly lang = input('');
  readonly code = input.required<string>();
  readonly testId = input<string | null>(null);

  private readonly clipboard = inject(Clipboard);

  protected readonly copied = signal(false);

  protected copy(): void {
    if (this.clipboard.copy(this.code())) {
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), COPIED_RESET_MS);
    }
  }
}
