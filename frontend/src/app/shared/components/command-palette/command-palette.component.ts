import {
  Component,
  ChangeDetectionStrategy,
  input,
  model,
  output,
  signal,
  computed,
  effect,
} from '@angular/core';
import { OverlayModule, type ConnectedPosition } from '@angular/cdk/overlay';
import { A11yModule } from '@angular/cdk/a11y';

export interface CommandItem {
  readonly id: string;
  readonly label: string;
  readonly group?: string;
  /** Optional leading glyph/emoji rendered before the label. */
  readonly icon?: string;
  /** Optional trailing meta (shortcut hint, category, etc.). */
  readonly meta?: string;
}

interface CommandGroup {
  readonly name: string | null;
  readonly items: readonly CommandItem[];
}

/**
 * DS command palette — `ui-command-palette`. A ⌘K-style launcher rendered in a
 * centered CDK overlay. `open` is a two-way model; a search input filters
 * `items` live, arrow keys move the active row, Enter emits the selected item,
 * and ESC / backdrop click closes. Focus is trapped while open
 * (`role=dialog` + `role=listbox`).
 */
@Component({
  selector: 'app-command-palette',
  imports: [OverlayModule, A11yModule],
  template: `
    <ng-template
      cdkConnectedOverlay
      [cdkConnectedOverlayOpen]="open()"
      [cdkConnectedOverlayPositions]="positions"
      [cdkConnectedOverlayHasBackdrop]="true"
      cdkConnectedOverlayBackdropClass="bg-overlay/60"
      [cdkConnectedOverlayWidth]="'560px'"
      (backdropClick)="close()"
      (overlayKeydown)="onKeydown($event)"
      (attach)="onAttach()"
      (detach)="close()"
    >
      <div
        class="flex max-h-[70vh] w-[560px] max-w-[calc(100vw-2rem)] flex-col overflow-hidden rounded-md border border-border bg-elevated shadow-[var(--shadow-2)]"
        role="dialog"
        aria-modal="true"
        [attr.aria-label]="ariaLabel()"
        [attr.data-testid]="testId()"
        cdkTrapFocus
        cdkTrapFocusAutoCapture
      >
        <div class="border-b border-border px-4 py-3">
          <input
            #search
            type="text"
            class="w-full border-none bg-transparent font-sans text-[16px] text-fg placeholder:text-fg-subtle focus:outline-hidden"
            role="combobox"
            aria-expanded="true"
            aria-controls="command-palette-list"
            [attr.aria-activedescendant]="activeId()"
            [placeholder]="placeholder()"
            [value]="query()"
            data-testid="command-palette-input"
            (input)="onQuery($event)"
          />
        </div>

        <div
          id="command-palette-list"
          class="max-h-[340px] overflow-y-auto p-2"
          role="listbox"
          [attr.aria-label]="ariaLabel()"
        >
          @for (group of groups(); track group.name) {
            @if (group.name) {
              <div
                class="px-2.5 pt-2 pb-1 font-mono text-[11px] tracking-[0.06em] text-fg-subtle uppercase"
              >
                {{ group.name }}
              </div>
            }
            @for (item of group.items; track item.id) {
              <button
                type="button"
                role="option"
                [id]="'command-option-' + item.id"
                [attr.aria-selected]="item.id === activeItemId()"
                [attr.data-testid]="'command-option-' + item.id"
                class="flex w-full cursor-pointer items-center gap-3 rounded-sm border-none bg-transparent px-2.5 py-[9px] text-left font-sans text-[13px] text-fg-muted transition-colors duration-[120ms] hover:bg-brand-faint hover:text-fg aria-selected:bg-brand-faint aria-selected:text-fg"
                (mouseenter)="setActiveById(item.id)"
                (click)="choose(item)"
              >
                @if (item.icon) {
                  <span
                    class="inline-flex w-4 shrink-0 justify-center"
                    aria-hidden="true"
                    >{{ item.icon }}</span
                  >
                }
                <span class="flex-1 truncate">{{ item.label }}</span>
                @if (item.meta) {
                  <span class="shrink-0 font-mono text-[11px] text-fg-subtle">{{
                    item.meta
                  }}</span>
                }
              </button>
            }
          } @empty {
            <div
              class="px-2.5 py-6 text-center font-sans text-[13px] text-fg-subtle"
            >
              {{ emptyText() }}
            </div>
          }
        </div>

        <div
          class="flex items-center gap-4 border-t border-border px-4 py-2.5 font-mono text-[11px] text-fg-subtle"
        >
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
        </div>
      </div>
    </ng-template>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CommandPaletteComponent {
  readonly open = model(false);
  readonly items = input.required<readonly CommandItem[]>();
  readonly placeholder = input('Type a command or search…');
  readonly ariaLabel = input('Command palette');
  readonly emptyText = input('No results found');
  readonly testId = input<string | null>(null);

  readonly selected = output<CommandItem>();

  /** Centered overlay: pin to the viewport center via a flexible position. */
  protected readonly positions: ConnectedPosition[] = [
    {
      originX: 'center',
      originY: 'center',
      overlayX: 'center',
      overlayY: 'top',
      offsetY: 0,
    },
  ];

  protected readonly query = signal('');
  private readonly activeIndex = signal(0);

  protected readonly filtered = computed<readonly CommandItem[]>(() => {
    const q = this.query().trim().toLowerCase();
    const all = this.items();
    if (!q) {
      return all;
    }
    return all.filter(
      (item) =>
        item.label.toLowerCase().includes(q) ||
        (item.group?.toLowerCase().includes(q) ?? false),
    );
  });

  protected readonly groups = computed<readonly CommandGroup[]>(() => {
    const out: CommandGroup[] = [];
    const index = new Map<string | null, CommandItem[]>();
    for (const item of this.filtered()) {
      const key = item.group ?? null;
      const bucket = index.get(key);
      if (bucket) {
        bucket.push(item);
      } else {
        const created = [item];
        index.set(key, created);
        out.push({ name: key, items: created });
      }
    }
    return out;
  });

  protected readonly activeItemId = computed<string | null>(() => {
    const list = this.filtered();
    if (list.length === 0) {
      return null;
    }
    const i = Math.min(this.activeIndex(), list.length - 1);
    return list[i].id;
  });

  protected readonly activeId = computed<string | null>(() => {
    const id = this.activeItemId();
    return id ? 'command-option-' + id : null;
  });

  constructor() {
    // Reset transient state whenever the palette opens.
    effect(() => {
      if (this.open()) {
        this.query.set('');
        this.activeIndex.set(0);
      }
    });
    // Keep the active index in range as the filtered list shrinks/grows.
    effect(() => {
      const len = this.filtered().length;
      if (len > 0 && this.activeIndex() > len - 1) {
        this.activeIndex.set(len - 1);
      }
    });
  }

  protected onAttach(): void {
    this.activeIndex.set(0);
  }

  protected close(): void {
    if (this.open()) {
      this.open.set(false);
    }
  }

  protected onQuery(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
    this.activeIndex.set(0);
  }

  protected setActiveById(id: string): void {
    const i = this.filtered().findIndex((item) => item.id === id);
    if (i >= 0) {
      this.activeIndex.set(i);
    }
  }

  protected choose(item: CommandItem): void {
    this.selected.emit(item);
    this.close();
  }

  protected onKeydown(event: KeyboardEvent): void {
    const list = this.filtered();
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        if (list.length > 0) {
          this.activeIndex.update((i) => (i + 1) % list.length);
        }
        break;
      case 'ArrowUp':
        event.preventDefault();
        if (list.length > 0) {
          this.activeIndex.update((i) => (i - 1 + list.length) % list.length);
        }
        break;
      case 'Enter': {
        event.preventDefault();
        const current = list[Math.min(this.activeIndex(), list.length - 1)];
        if (current) {
          this.choose(current);
        }
        break;
      }
      case 'Escape':
        event.preventDefault();
        this.close();
        break;
      default:
        break;
    }
  }
}
