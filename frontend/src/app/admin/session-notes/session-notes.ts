import {
  Component,
  ChangeDetectionStrategy,
  inject,
  input,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Notebook,
  RefreshCw,
  Loader2,
  ChevronDown,
  ChevronRight,
} from 'lucide-angular';
import { SessionNoteService } from '../../core/services/session-note.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiSessionNote } from '../../core/models';

/** note_type 對應的 badge 樣式 */
const TYPE_CLASSES: Record<string, string> = {
  plan: 'border-sky-800 bg-sky-900/30 text-sky-400',
  reflection: 'border-violet-800 bg-violet-900/30 text-violet-400',
  metrics: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
  insight: 'border-amber-800 bg-amber-900/30 text-amber-400',
  context: 'border-zinc-600 bg-zinc-800 text-zinc-300',
};

const DEFAULT_TYPE_CLASS = 'border-zinc-700 bg-zinc-800 text-zinc-400';

const NOTE_TYPES = [
  'plan',
  'reflection',
  'metrics',
  'insight',
  'context',
] as const;

@Component({
  selector: 'app-session-notes',
  standalone: true,
  imports: [FormsModule, LucideAngularModule],
  templateUrl: './session-notes.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SessionNotesComponent implements OnInit {
  readonly hideHeader = input(false);

  private readonly sessionNoteService = inject(SessionNoteService);
  private readonly markdownService = inject(MarkdownService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  // ─── State ───
  protected readonly notes = signal<ApiSessionNote[]>([]);
  protected readonly typeFilter = signal<string | null>(null);
  protected readonly daysFilter = signal(14);
  protected readonly isLoading = signal(true);
  protected readonly expandedNotes = signal<Set<number>>(new Set());

  // ─── Derived ───
  protected readonly filteredNotes = computed(() => {
    const type = this.typeFilter();
    return type
      ? this.notes().filter((n) => n.note_type === type)
      : this.notes();
  });

  // ─── Constants for template ───
  protected readonly noteTypes = NOTE_TYPES;

  // ─── Icons ───
  protected readonly NotebookIcon = Notebook;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly Loader2Icon = Loader2;
  protected readonly ChevronDownIcon = ChevronDown;
  protected readonly ChevronRightIcon = ChevronRight;

  ngOnInit(): void {
    this.loadNotes();
  }

  protected loadNotes(): void {
    this.isLoading.set(true);
    this.parsedMarkdownCache.set(new Map());
    this.sessionNoteService
      .list(undefined, undefined, this.daysFilter())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.notes.set(data);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 Session Notes');
          this.isLoading.set(false);
        },
      });
  }

  protected setTypeFilter(type: string | null): void {
    this.typeFilter.set(type);
  }

  protected updateDays(days: number): void {
    this.daysFilter.set(days);
    this.loadNotes();
  }

  protected toggleNote(id: number): void {
    this.expandedNotes.update((set) => {
      const next = new Set(set);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  protected isExpanded(id: number): boolean {
    return this.expandedNotes().has(id);
  }

  protected typeClass(noteType: string): string {
    return TYPE_CLASSES[noteType] ?? DEFAULT_TYPE_CLASS;
  }

  // SECURITY_REVIEW: MarkdownService.parse() sanitizes output via DOMPurify with strict allowlist
  protected parsedMarkdownCache = signal<Map<number, string>>(new Map());

  protected getParsedMarkdown(id: number, content: string): string {
    const cache = this.parsedMarkdownCache();
    if (cache.has(id)) {
      return cache.get(id)!;
    }
    const parsed = this.markdownService.parse(content);
    this.parsedMarkdownCache.update((m) => {
      const next = new Map(m);
      next.set(id, parsed);
      return next;
    });
    return parsed;
  }
}
