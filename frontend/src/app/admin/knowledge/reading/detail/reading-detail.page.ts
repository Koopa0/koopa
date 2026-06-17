import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  signal,
} from '@angular/core';
import {
  rxResource,
  takeUntilDestroyed,
  toSignal,
} from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { map } from 'rxjs';
import {
  ReadingService,
  todayISODate,
  type ReadingDetail,
  type ReadingStatus,
  type UpdateReadingRequest,
} from '../../../../core/services/reading.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

/** Status options in shelf order, with the warmer "set aside" label. */
const STATUS_OPTIONS: readonly { status: ReadingStatus; label: string }[] = [
  { status: 'want_to_read', label: 'Want to read' },
  { status: 'reading', label: 'Reading' },
  { status: 'finished', label: 'Finished' },
  { status: 'abandoned', label: 'Set aside' },
] as const;

/**
 * Book page — header (serif title, author, status, dates) over the
 * reading diary: reflections in entry_date order with a serif voice,
 * and an always-present composer at the thread's end. Deleting the
 * book lives in the overflow menu and takes the diary with it.
 */
@Component({
  selector: 'app-reading-detail-page',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './reading-detail.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class ReadingDetailPageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly readingService = inject(ReadingService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<ReadingDetail, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.readingService.detail(params),
  });

  protected readonly book = computed(() =>
    this.resource.hasValue() ? this.resource.value() : undefined,
  );
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.book(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly statusOptions = STATUS_OPTIONS;

  /** True while any write is in flight — gates all mutating controls. */
  protected readonly saving = signal(false);

  // Overflow menu
  protected readonly menuOpen = signal(false);

  // Composer (always present at the thread's end)
  protected readonly draftBody = signal('');
  protected readonly draftDate = signal(todayISODate());
  protected readonly canPost = computed(
    () => this.draftBody().trim().length > 0 && !this.saving(),
  );

  // Per-entry editing
  protected readonly editingId = signal<string | null>(null);
  protected readonly editBody = signal('');
  protected readonly editDate = signal('');

  constructor() {
    this.topbar.set({ title: 'Reading', crumbs: ['Knowledge', 'Reading'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
    effect(() => {
      const b = this.book();
      if (b) {
        this.topbar.set({ title: b.title, crumbs: ['Knowledge', 'Reading'] });
      }
    });
  }

  // ── Book header ────────────────────────────────────────────────

  protected setStatus(value: string): void {
    this.updateBook(
      { status: value as ReadingStatus },
      "Couldn't change the status.",
    );
  }

  /** Date inputs PUT only a set value — a recorded date cannot be
   *  cleared back to null through this endpoint. */
  protected setStartedOn(value: string): void {
    if (!value) return;
    this.updateBook({ started_on: value }, "Couldn't save the start date.");
  }

  protected setFinishedOn(value: string): void {
    if (!value) return;
    this.updateBook({ finished_on: value }, "Couldn't save the finish date.");
  }

  protected toggleVisibility(): void {
    const b = this.book();
    if (!b) return;
    this.menuOpen.set(false);
    this.updateBook(
      { is_public: !b.is_public },
      "Couldn't change the visibility.",
    );
  }

  protected deleteBook(): void {
    const b = this.book();
    if (!b || this.saving()) return;
    this.menuOpen.set(false);

    const entries = b.reflections.length;
    const diary =
      entries === 0
        ? 'Its diary goes with it.'
        : entries === 1
          ? 'Its 1 diary entry goes with it.'
          : `Its ${entries} diary entries go with it.`;
    if (!window.confirm(`Delete "${b.title}"? ${diary}`)) return;

    this.saving.set(true);
    this.readingService
      .remove(b.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notifications.success(`Removed "${b.title}" from the shelf`);
          this.router.navigate(['/admin/knowledge/reading']);
        },
        error: () => {
          this.saving.set(false);
          this.notifications.error(`Couldn't delete "${b.title}".`);
        },
      });
  }

  // ── Diary thread ───────────────────────────────────────────────

  protected postEntry(): void {
    const b = this.book();
    if (!b || !this.canPost()) return;

    this.saving.set(true);
    this.readingService
      .addReflection(b.id, {
        body: this.draftBody().trim(),
        entry_date: this.draftDate() || undefined,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.saving.set(false);
          this.draftBody.set('');
          this.draftDate.set(todayISODate());
          this.resource.reload();
        },
        error: () => {
          this.saving.set(false);
          this.notifications.error("Couldn't save the entry. It's still here — try again.");
        },
      });
  }

  protected startEditing(entryId: string): void {
    const entry = this.book()?.reflections.find((r) => r.id === entryId);
    if (!entry) return;
    this.editingId.set(entryId);
    this.editBody.set(entry.body);
    this.editDate.set(entry.entry_date);
  }

  protected cancelEditing(): void {
    this.editingId.set(null);
  }

  protected saveEntry(): void {
    const b = this.book();
    const id = this.editingId();
    if (!b || !id || this.saving()) return;
    const body = this.editBody().trim();
    if (!body) return;

    this.saving.set(true);
    this.readingService
      .updateReflection(b.id, id, { body, entry_date: this.editDate() })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.saving.set(false);
          this.editingId.set(null);
          this.resource.reload();
        },
        error: () => {
          this.saving.set(false);
          this.notifications.error("Couldn't save the changes.");
        },
      });
  }

  protected deleteEntry(entryId: string): void {
    const b = this.book();
    if (!b || this.saving()) return;
    if (!window.confirm('Delete this entry? This cannot be undone.')) return;

    this.saving.set(true);
    this.readingService
      .removeReflection(b.id, entryId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.saving.set(false);
          this.resource.reload();
        },
        error: () => {
          this.saving.set(false);
          this.notifications.error("Couldn't delete the entry.");
        },
      });
  }

  /** Typed accessor for input/select/textarea values in the template. */
  protected readValue(event: Event): string {
    return (
      event.target as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
    ).value;
  }

  private updateBook(request: UpdateReadingRequest, failure: string): void {
    const b = this.book();
    if (!b || this.saving()) return;

    this.saving.set(true);
    this.readingService
      .update(b.id, request)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.saving.set(false);
          this.resource.reload();
        },
        error: () => {
          this.saving.set(false);
          this.notifications.error(failure);
        },
      });
  }
}
