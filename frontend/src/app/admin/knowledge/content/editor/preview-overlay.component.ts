import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  output,
} from '@angular/core';
import { A11yModule } from '@angular/cdk/a11y';
import type { ApiContent } from '../../../../core/models/api.model';
import { contentTypeRoute } from '../../../../core/models/content-type.config';
import { ArticleDetailComponent } from '../../../../pages/article-detail/article-detail';

/**
 * Publish-preview overlay for the content snapshot already loaded by the
 * editor. It renders the shared reading component inline, so private drafts do
 * not cross the public API boundary and unsaved form edits cannot masquerade
 * as the persisted snapshot.
 *
 * Closes on Escape, on scrim mousedown, and via the Close button.
 * The bar shows the public URL form and whether that saved snapshot is live.
 */
@Component({
  selector: 'app-content-preview-overlay',
  imports: [A11yModule, ArticleDetailComponent],
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
            saved snapshot ·
            {{ isLive() ? 'live on the public site' : 'not public' }}
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
        <div
          class="ed flex-1 overflow-y-auto bg-bg"
          data-tone="b"
          data-testid="preview-content"
        >
          <app-article-detail
            class="block min-h-full"
            [article]="content()"
            [preview]="true"
          />
        </div>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    '(document:keydown.escape)': 'closed.emit()',
  },
})
export class ContentPreviewOverlayComponent {
  /** Persisted API snapshot; never constructed from the editor form. */
  readonly content = input.required<ApiContent>();

  readonly closed = output();

  protected readonly isLive = computed(
    () => this.content().status === 'published' && this.content().is_public,
  );

  /**
   * Public URL form shown in the bar (display only). Every content type
   * resolves to the consolidated /articles detail route — the standalone
   * per-type routes (/build-logs, /til, …) are retired — so the canonical
   * URL is sourced from contentTypeRoute rather than the bare type slug.
   */
  protected readonly displayUrl = computed(
    () =>
      `koopa0.dev${contentTypeRoute(this.content().type)}/${this.content().slug}`,
  );
}
