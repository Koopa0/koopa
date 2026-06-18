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
import { SongService, type Song } from '../../../../core/services/song.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

/** Label for the trailing group of songs with no album recorded. */
const NO_ALBUM_LABEL = 'No album';

interface ShelfGroup {
  /** Album name, or `''` for the no-album group. Used as the @for track. */
  album: string;
  label: string;
  rows: Song[];
}

const ADD_FORM_DEFAULTS = {
  title: '',
  album: '',
};

/**
 * ヨルシカ song shelf — the listening counterpart of the reading shelf.
 * Tracks grouped by album in most-recently-touched order (songs with no
 * album recorded fall into a trailing "No album" group), with an inline
 * add form. Rows link to the song page (study layer + diary thread). No
 * rating, no score, no progress — reflections are the only evaluation.
 */
@Component({
  selector: 'app-song-shelf-page',
  imports: [RouterLink],
  templateUrl: './song-shelf.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class SongShelfPageComponent {
  private readonly songService = inject(SongService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource<Song[], void>({
    stream: () => this.songService.list(),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). hasError() drives
  // the error banner; without this guard a failed list read throws here.
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

  /**
   * Album groups in first-appearance order over the updated_at-desc list,
   * so the most-recently-touched album leads. Songs with no album collapse
   * into a single trailing "No album" group.
   */
  protected readonly groups = computed<ShelfGroup[]>(() => {
    const withAlbum = new Map<string, Song[]>();
    const noAlbum: Song[] = [];
    for (const song of this.rows()) {
      if (song.album) {
        const bucket = withAlbum.get(song.album);
        if (bucket) {
          bucket.push(song);
        } else {
          withAlbum.set(song.album, [song]);
        }
      } else {
        noAlbum.push(song);
      }
    }
    const groups: ShelfGroup[] = [];
    for (const [album, rows] of withAlbum) {
      groups.push({ album, label: album, rows });
    }
    if (noAlbum.length > 0) {
      groups.push({ album: '', label: NO_ALBUM_LABEL, rows: noAlbum });
    }
    return groups;
  });

  // Inline add form
  protected readonly addFormOpen = signal(false);
  protected readonly newTitle = signal(ADD_FORM_DEFAULTS.title);
  protected readonly newAlbum = signal(ADD_FORM_DEFAULTS.album);
  protected readonly submitting = signal(false);
  protected readonly canSubmit = computed(
    () => this.newTitle().trim().length > 0 && !this.submitting(),
  );

  constructor() {
    this.topbar.set({ title: 'ヨルシカ', crumbs: ['Knowledge', 'ヨルシカ'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected openAddForm(): void {
    this.addFormOpen.set(true);
  }

  protected cancelAddForm(): void {
    this.addFormOpen.set(false);
    this.resetAddForm();
  }

  /** Typed accessor for input values in the template. */
  protected readValue(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected addSong(): void {
    if (!this.canSubmit()) return;

    const title = this.newTitle().trim();
    const album = this.newAlbum().trim();
    this.submitting.set(true);

    this.songService
      .create({ title_ja: title, album: album || undefined })
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

  private resetAddForm(): void {
    this.newTitle.set(ADD_FORM_DEFAULTS.title);
    this.newAlbum.set(ADD_FORM_DEFAULTS.album);
  }
}
