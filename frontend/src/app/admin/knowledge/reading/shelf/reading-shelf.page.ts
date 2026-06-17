import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource, takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import {
  ReadingService,
  todayISODate,
  type Reading,
  type ReadingStatus,
} from '../../../../core/services/reading.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

/** Shelf group order: the book in hand first, then intent, then history. */
const GROUP_ORDER: readonly { status: ReadingStatus; label: string }[] = [
  { status: 'reading', label: 'Reading' },
  { status: 'want_to_read', label: 'Want to read' },
  { status: 'finished', label: 'Finished' },
  { status: 'abandoned', label: 'Set aside' },
] as const;

interface ShelfGroup {
  status: ReadingStatus;
  label: string;
  rows: Reading[];
}

const ADD_FORM_DEFAULTS = {
  title: '',
  author: '',
  status: 'want_to_read' as ReadingStatus,
};

/**
 * Reading shelf — the one "life" page in the admin. Books grouped by
 * status (reading / want to read / finished / set aside), one-click
 * start/finish transitions, and an inline add form. Rows link to the
 * book page (diary thread). No ratings, no streaks — reflections are
 * the only evaluation, and "set aside" is a legitimate resting place.
 */
@Component({
  selector: 'app-reading-shelf-page',
  standalone: true,
  imports: [RouterLink],
  templateUrl: './reading-shelf.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class ReadingShelfPageComponent {
  private readonly readingService = inject(ReadingService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource<Reading[], void>({
    stream: () => this.readingService.list(),
  });

  protected readonly rows = computed(() =>
    this.resource.hasValue() ? this.resource.value() : [],
  );
  protected readonly total = computed(() => this.rows().length);
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.resource.hasValue(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );
  protected readonly isEmpty = computed(
    () => !this.isLoading() && !this.hasError() && this.rows().length === 0,
  );

  /** Non-empty groups in shelf order — empty groups stay silent. */
  protected readonly groups = computed<ShelfGroup[]>(() => {
    const rows = this.rows();
    return GROUP_ORDER.map(({ status, label }) => ({
      status,
      label,
      rows: rows.filter((r) => r.status === status),
    })).filter((g) => g.rows.length > 0);
  });

  // Inline add form
  protected readonly addFormOpen = signal(false);
  protected readonly newTitle = signal(ADD_FORM_DEFAULTS.title);
  protected readonly newAuthor = signal(ADD_FORM_DEFAULTS.author);
  protected readonly newStatus = signal<ReadingStatus>(ADD_FORM_DEFAULTS.status);
  protected readonly submitting = signal(false);
  protected readonly canSubmit = computed(
    () => this.newTitle().trim().length > 0 && !this.submitting(),
  );

  /** Reading id with an in-flight quick action; disables its buttons. */
  protected readonly pendingId = signal<string | null>(null);

  protected readonly statusOptions = GROUP_ORDER;

  constructor() {
    this.topbar.set({ title: 'Reading', crumbs: ['Knowledge', 'Reading'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected openAddForm(): void {
    this.addFormOpen.set(true);
  }

  protected cancelAddForm(): void {
    this.addFormOpen.set(false);
    this.resetAddForm();
  }

  protected setNewStatus(value: string): void {
    this.newStatus.set(value as ReadingStatus);
  }

  /** Typed accessor for input/select values in the template. */
  protected readValue(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement).value;
  }

  protected addBook(): void {
    if (!this.canSubmit()) return;

    const title = this.newTitle().trim();
    const author = this.newAuthor().trim();
    this.submitting.set(true);

    this.readingService
      .create({
        title,
        author: author || undefined,
        status: this.newStatus(),
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.submitting.set(false);
          this.addFormOpen.set(false);
          this.resetAddForm();
          this.notifications.success(`Added "${title}" to the shelf`);
          this.resource.reload();
        },
        error: () => {
          this.submitting.set(false);
          this.notifications.error(`Couldn't add "${title}". Try again.`);
        },
      });
  }

  /** One click: want_to_read → reading, stamping started_on locally
   *  when the book has no start date yet. */
  protected startReading(book: Reading): void {
    this.transition(book, {
      status: 'reading',
      ...(book.started_on ? {} : { started_on: todayISODate() }),
    });
  }

  /** One click: reading → finished. No date sent — the server stamps
   *  today, and never overwrites an already-recorded date. */
  protected finishReading(book: Reading): void {
    this.transition(book, { status: 'finished' });
  }

  private transition(
    book: Reading,
    request: { status: ReadingStatus; started_on?: string },
  ): void {
    if (this.pendingId()) return;
    this.pendingId.set(book.id);

    this.readingService
      .update(book.id, request)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.pendingId.set(null);
          this.resource.reload();
        },
        error: () => {
          this.pendingId.set(null);
          this.notifications.error(`Couldn't update "${book.title}".`);
        },
      });
  }

  /** Quiet date annotation per row — only what the shelf state implies. */
  protected dateLabel(book: Reading): string {
    switch (book.status) {
      case 'reading':
        return book.started_on ? `since ${book.started_on}` : '';
      case 'finished':
        return book.finished_on ? `finished ${book.finished_on}` : '';
      case 'abandoned':
        return book.started_on ? `started ${book.started_on}` : '';
      default:
        return '';
    }
  }

  private resetAddForm(): void {
    this.newTitle.set(ADD_FORM_DEFAULTS.title);
    this.newAuthor.set(ADD_FORM_DEFAULTS.author);
    this.newStatus.set(ADD_FORM_DEFAULTS.status);
  }
}
