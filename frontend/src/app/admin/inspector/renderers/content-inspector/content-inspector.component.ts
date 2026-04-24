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
import { ContentService } from '../../../../core/services/content.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { InspectorService } from '../../inspector.service';
import type { ApiContent } from '../../../../core/models/api.model';

type ContentTab = 'preview' | 'metadata';

/**
 * Content Inspector renderer — Preview tab with prose + Metadata tab.
 *
 * Action bar: Publish / Revert to draft (with notes) / Public toggle.
 * Uses existing REST endpoints:
 *   GET  /api/admin/knowledge/content/{id}
 *   POST /api/admin/knowledge/content/{id}/publish
 *   POST /api/admin/knowledge/content/{id}/revert-to-draft
 *   PATCH /api/admin/knowledge/content/{id}/is-public
 */
@Component({
  selector: 'app-content-inspector',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './content-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ContentInspectorComponent {
  readonly id = input.required<string>();

  private readonly contentService = inject(ContentService);
  private readonly inspector = inject(InspectorService);
  private readonly notifications = inject(NotificationService);

  protected readonly activeTab = signal<ContentTab>('preview');
  protected readonly rejectNotes = signal('');
  protected readonly isRejectExpanded = signal(false);
  protected readonly isActioning = signal(false);

  protected readonly resource = rxResource<ApiContent, string>({
    params: () => this.id(),
    stream: ({ params }) => this.contentService.adminGet(params),
  });

  protected readonly content = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly isReviewable = computed(() => {
    const c = this.content();
    return c?.status === 'review' || c?.status === 'draft';
  });

  protected readonly reviewNotes = computed(() => {
    const meta = this.content()?.ai_metadata;
    if (!meta || typeof meta !== 'object') return null;
    const notes = (meta as Record<string, unknown>)['review_notes'];
    return typeof notes === 'string' ? notes : null;
  });

  protected setTab(tab: ContentTab): void {
    this.activeTab.set(tab);
  }

  protected toggleReject(): void {
    this.isRejectExpanded.update((v) => !v);
  }

  protected publish(): void {
    const c = this.content();
    if (!c || this.isActioning()) return;

    this.isActioning.set(true);
    this.contentService.publish(c.id).subscribe({
      next: () => {
        this.isActioning.set(false);
        this.inspector.recordAction('content', c.id, 'publish');
        this.notifications.undo(`Published "${c.title}"`, () => {
          // Undo: revert to draft
          this.contentService
            .update(c.id, { status: 'draft' })
            .subscribe(() => this.resource.reload());
        });
      },
      error: () => {
        this.isActioning.set(false);
        this.notifications.error('Failed to publish content.');
      },
    });
  }

  protected reject(): void {
    const c = this.content();
    const notes = this.rejectNotes().trim();
    if (!c || !notes || this.isActioning()) return;

    this.isActioning.set(true);
    this.contentService.revertToDraft(c.id, notes).subscribe({
      next: () => {
        this.isActioning.set(false);
        this.rejectNotes.set('');
        this.isRejectExpanded.set(false);
        this.inspector.recordAction('content', c.id, 'reject');
        this.notifications.undo(`Reverted "${c.title}" to draft`, () => {
          // Undo: push back to review (no backend "unrevert" endpoint).
          this.contentService
            .update(c.id, { status: 'review' })
            .subscribe(() => this.resource.reload());
        });
      },
      error: () => {
        this.isActioning.set(false);
        this.notifications.error('Failed to revert content to draft.');
      },
    });
  }

  protected togglePublic(): void {
    const c = this.content();
    if (!c || this.isActioning()) return;

    this.isActioning.set(true);
    this.contentService.setVisibility(c.id, !c.is_public).subscribe({
      next: () => {
        this.isActioning.set(false);
        this.resource.reload();
      },
      error: () => {
        this.isActioning.set(false);
      },
    });
  }

  protected readTextarea(event: Event): string {
    return (event.target as HTMLTextAreaElement).value;
  }
}
