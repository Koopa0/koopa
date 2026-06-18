import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  linkedSignal,
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
  SongService,
  todayISODate,
  type SongDetail,
  type UpdateSongRequest,
} from '../../../../core/services/song.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

/**
 * Song page — header (serif 曲名 + album) over an editable study layer
 * (lyrics_ja, an owner translation, vocabulary notes) and the reflection
 * diary: entries in entry_date order with an always-present composer.
 * The study fields seed from the loaded song via linkedSignal so a save +
 * reload re-syncs the drafts without an effect resetting in-flight edits.
 * Deleting the song lives in the overflow menu and takes the diary with it.
 */
@Component({
  selector: 'app-song-detail-page',
  imports: [RouterLink],
  templateUrl: './song-detail.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class SongDetailPageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly songService = inject(SongService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<SongDetail, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.songService.detail(params),
  });

  protected readonly song = computed(() =>
    this.resource.hasValue() ? this.resource.value() : undefined,
  );
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.song(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  /** True while any write is in flight — gates all mutating controls. */
  protected readonly saving = signal(false);

  // Overflow menu
  protected readonly menuOpen = signal(false);

  // Editable study layer — seeded from the loaded song, overridable while
  // editing. linkedSignal re-syncs each draft when the song reloads (after
  // a save), which an effect-driven copy would do wrong (it would reset
  // in-flight edits on every external change).
  protected readonly titleDraft = linkedSignal(
    () => this.song()?.title_ja ?? '',
  );
  protected readonly albumDraft = linkedSignal(() => this.song()?.album ?? '');
  protected readonly lyricsDraft = linkedSignal(
    () => this.song()?.lyrics_ja ?? '',
  );
  protected readonly translationDraft = linkedSignal(
    () => this.song()?.translation ?? '',
  );
  protected readonly vocabularyDraft = linkedSignal(
    () => this.song()?.vocabulary ?? '',
  );

  /** The study layer has unsaved edits relative to the stored song. */
  protected readonly studyDirty = computed(() => {
    const s = this.song();
    if (!s) return false;
    return (
      this.titleDraft() !== s.title_ja ||
      this.albumDraft() !== s.album ||
      this.lyricsDraft() !== s.lyrics_ja ||
      this.translationDraft() !== s.translation ||
      this.vocabularyDraft() !== s.vocabulary
    );
  });

  protected readonly canSaveStudy = computed(
    () =>
      this.studyDirty() &&
      this.titleDraft().trim().length > 0 &&
      !this.saving(),
  );

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
    this.topbar.set({ title: 'ヨルシカ', crumbs: ['Knowledge', 'ヨルシカ'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
    effect(() => {
      const s = this.song();
      if (s) {
        this.topbar.set({
          title: s.title_ja,
          crumbs: ['Knowledge', 'ヨルシカ'],
        });
      }
    });
  }

  // ── Study layer ────────────────────────────────────────────────

  /** PUT the whole study layer (title, album, lyrics, translation,
   *  vocabulary). title/album are single-line — trimmed before send. */
  protected saveStudy(): void {
    if (!this.canSaveStudy()) return;
    this.updateSong(
      {
        title_ja: this.titleDraft().trim(),
        album: this.albumDraft().trim(),
        lyrics_ja: this.lyricsDraft(),
        translation: this.translationDraft(),
        vocabulary: this.vocabularyDraft(),
      },
      "Couldn't save the study fields.",
    );
  }

  protected toggleVisibility(): void {
    const s = this.song();
    if (!s) return;
    this.menuOpen.set(false);
    this.updateSong(
      { is_public: !s.is_public },
      "Couldn't change the visibility.",
    );
  }

  protected deleteSong(): void {
    const s = this.song();
    if (!s || this.saving()) return;
    this.menuOpen.set(false);

    const entries = s.reflections.length;
    const diary =
      entries === 0
        ? 'Its diary goes with it.'
        : entries === 1
          ? 'Its 1 diary entry goes with it.'
          : `Its ${entries} diary entries go with it.`;
    if (!window.confirm(`Delete "${s.title_ja}"? ${diary}`)) return;

    this.saving.set(true);
    this.songService
      .remove(s.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.notifications.success(`Removed "${s.title_ja}" from the shelf`);
          this.router.navigate(['/admin/knowledge/song']);
        },
        error: () => {
          this.saving.set(false);
          this.notifications.error(`Couldn't delete "${s.title_ja}".`);
        },
      });
  }

  // ── Diary thread ───────────────────────────────────────────────

  protected postEntry(): void {
    const s = this.song();
    if (!s || !this.canPost()) return;

    this.saving.set(true);
    this.songService
      .addReflection(s.id, {
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
          this.notifications.error(
            "Couldn't save the entry. It's still here — try again.",
          );
        },
      });
  }

  protected startEditing(entryId: string): void {
    const entry = this.song()?.reflections.find((r) => r.id === entryId);
    if (!entry) return;
    this.editingId.set(entryId);
    this.editBody.set(entry.body);
    this.editDate.set(entry.entry_date);
  }

  protected cancelEditing(): void {
    this.editingId.set(null);
  }

  protected saveEntry(): void {
    const s = this.song();
    const id = this.editingId();
    if (!s || !id || this.saving()) return;
    const body = this.editBody().trim();
    if (!body) return;

    this.saving.set(true);
    this.songService
      .updateReflection(s.id, id, { body, entry_date: this.editDate() })
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
    const s = this.song();
    if (!s || this.saving()) return;
    if (!window.confirm('Delete this entry? This cannot be undone.')) return;

    this.saving.set(true);
    this.songService
      .removeReflection(s.id, entryId)
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

  /** Typed accessor for input/textarea values in the template. */
  protected readValue(event: Event): string {
    return (event.target as HTMLInputElement | HTMLTextAreaElement).value;
  }

  private updateSong(request: UpdateSongRequest, failure: string): void {
    const s = this.song();
    if (!s || this.saving()) return;

    this.saving.set(true);
    this.songService
      .update(s.id, request)
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
