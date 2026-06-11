import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  output,
} from '@angular/core';
import { DomSanitizer, type SafeResourceUrl } from '@angular/platform-browser';
import { A11yModule } from '@angular/cdk/a11y';
import type { ContentType } from '../../../../core/models/api.model';

/**
 * Publish-preview overlay: a scrim-centered frame whose iframe renders
 * the chrome-less public reading surface at `/preview/{slug}`.
 *
 * Closes on Escape, on scrim mousedown, and via the Close button.
 * The bar shows the public URL form and whether the preview reflects
 * the live article (published) or a pre-publish state.
 */
@Component({
  selector: 'app-content-preview-overlay',
  standalone: true,
  imports: [A11yModule],
  template: `
    <div
      class="fixed inset-0 z-[100] grid place-items-center bg-black/60"
      (mousedown)="closed.emit()"
      data-testid="preview-scrim"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Publish preview"
        cdkTrapFocus
        cdkTrapFocusAutoCapture
        class="flex h-[min(88vh,920px)] w-[min(980px,94vw)] flex-col overflow-hidden rounded-lg border border-border-strong bg-panel shadow-[var(--shadow-2)]"
        (mousedown)="$event.stopPropagation()"
        data-testid="preview-frame"
      >
        <div
          class="flex shrink-0 items-center gap-3 border-b border-border bg-elevated px-3.5 py-2.5"
        >
          <span
            class="font-mono text-[11px] uppercase tracking-[0.04em] text-brand"
            data-testid="preview-live"
          >
            Publish preview
          </span>
          <span
            class="rounded-sm border border-border-faint bg-bg px-[9px] py-[3px] font-mono text-[11px] text-fg-muted"
            data-testid="preview-url"
          >
            {{ displayUrl() }}
          </span>
          <span
            class="hidden font-mono text-[10px] text-fg-faint sm:inline"
            data-testid="preview-note"
          >
            renders the live public article component ·
            {{ live() ? 'live preview' : 'draft preview' }}
          </span>
          <span class="flex-1"></span>
          <button
            type="button"
            (click)="closed.emit()"
            class="rounded-sm px-2.5 py-1 text-xs text-fg-muted transition-colors hover:bg-overlay hover:text-fg"
            data-testid="preview-close"
          >
            Close
          </button>
        </div>
        <iframe
          [src]="iframeSrc()"
          title="Publish preview"
          class="block w-full flex-1 border-0 bg-bg"
          data-testid="preview-iframe"
        ></iframe>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    '(document:keydown.escape)': 'closed.emit()',
  },
})
export class ContentPreviewOverlayComponent {
  readonly slug = input.required<string>();
  readonly type = input.required<ContentType>();
  /** True when the content is published — the iframe shows the live article. */
  readonly live = input(false);

  readonly closed = output();

  private readonly sanitizer = inject(DomSanitizer);

  /**
   * Same-origin preview route for the iframe.
   *
   * SECURITY_REVIEW: bypassSecurityTrustResourceUrl is safe here — the
   * URL is built from the constant `/preview/` prefix plus a
   * URI-encoded path segment, so no caller-controlled scheme, host, or
   * path traversal can reach the iframe src.
   */
  protected readonly iframeSrc = computed<SafeResourceUrl>(() =>
    this.sanitizer.bypassSecurityTrustResourceUrl(
      `/preview/${encodeURIComponent(this.slug())}`,
    ),
  );

  /** Public URL form shown in the bar (display only). */
  protected readonly displayUrl = computed(
    () => `koopa0.dev/${this.type()}/${this.slug()}`,
  );
}
