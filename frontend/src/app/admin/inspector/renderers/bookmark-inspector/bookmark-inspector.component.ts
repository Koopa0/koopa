import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { LucideAngularModule, Copy as CopyIcon } from 'lucide-angular';
import { BookmarkService } from '../../../../core/services/bookmark.service';
import type { BookmarkDetail } from '../../../../core/models/workbench.model';

const URL_TRUNCATE_AT = 60;

/**
 * Bookmark Inspector — the bookmark is a URL plus Koopa's note about
 * why he saved it, nothing more.
 *
 * Layout:
 *   Header       — title + copy URL button + subtitle (host · visibility)
 *   External URL — middle-ellipsis truncation; full URL in title /
 *                  aria-label; rendered with `rel="noopener noreferrer
 *                  nofollow"`
 *   Note + Excerpt — semantic `<dl>` peers
 *   Topics + tags chip rows (hidden when empty)
 *   Tail lines conditional: source feed · non-default channel ·
 *                  non-human curator
 *
 * Read-only: mutation lives in the admin bookmarks surface, not here.
 */
@Component({
  selector: 'app-bookmark-inspector',
  standalone: true,
  imports: [DatePipe, ClipboardModule, LucideAngularModule],
  templateUrl: './bookmark-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BookmarkInspectorComponent {
  readonly id = input.required<string>();

  private readonly bookmarkService = inject(BookmarkService);

  protected readonly justCopied = signal(false);
  protected readonly CopyIcon = CopyIcon;

  protected readonly resource = rxResource<BookmarkDetail, string>({
    params: () => this.id(),
    stream: ({ params }) => this.bookmarkService.get(params),
  });

  protected readonly bookmark = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  /**
   * Middle-ellipsis URL truncation.
   * "https://example.com/long/path/to/article-slug" → "example.com/.../article-slug" if > 60 chars.
   * Full URL accessible via title attr + aria-label on the anchor.
   */
  protected readonly truncatedUrl = computed(() => {
    const b = this.bookmark();
    if (!b) return '';
    // Strip scheme for cleaner display; full URL still in href.
    const display = b.url.replace(/^https?:\/\//, '');
    if (display.length <= URL_TRUNCATE_AT) return display;
    const head = display.slice(0, 24);
    const tail = display.slice(-30);
    return `${head}…${tail}`;
  });

  /** True when capture_channel is non-default (anything but 'manual'). */
  protected readonly showCaptureChannel = computed(() => {
    const b = this.bookmark();
    return !!b && b.capture_channel !== 'manual';
  });

  /** True when curated_by is non-default (anything but 'human'). */
  protected readonly showCuratedBy = computed(() => {
    const b = this.bookmark();
    return !!b && b.curated_by !== 'human';
  });

  /** True when updated_at differs from curated_at (avoid duplicate timestamp). */
  protected readonly showUpdated = computed(() => {
    const b = this.bookmark();
    return !!b && b.updated_at !== b.curated_at;
  });

  protected onCopyBookmarkUrl(): void {
    this.justCopied.set(true);
    setTimeout(() => this.justCopied.set(false), 1500);
  }
}
