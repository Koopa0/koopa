---
name: angular-cdk
description: >-
  Angular CDK usage patterns — Overlay, A11y, Virtual Scrolling, DragDrop,
  Portal, and other headless UI behavior modules.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular CDK

## 觸發條件

當元件需要以下底層行為時使用此 skill：
- 浮層定位（Dropdown, Tooltip, Popover, Select）
- 焦點管理（Focus trap, Focus monitor, Keyboard navigation）
- 虛擬捲動（長列表 > 50 筆）
- 拖放排序
- 響應式斷點偵測
- 剪貼簿操作
- 無頭 Dialog 系統
- Auto-resize textarea

## CDK Overlay 模式

### 基礎 Overlay（Dropdown / Tooltip / Popover）

```typescript
import { Component, inject, signal, ElementRef, viewChild } from '@angular/core';
import { Overlay, OverlayRef, OverlayModule, ConnectedPosition } from '@angular/cdk/overlay';
import { ComponentPortal, PortalModule } from '@angular/cdk/portal';

@Component({
  selector: 'app-dropdown',
  standalone: true,
  imports: [OverlayModule, PortalModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <button
      #trigger
      data-testid="dropdown-trigger"
      (click)="toggle()"
      class="inline-flex items-center gap-x-1 text-sm font-semibold text-zinc-900 dark:text-zinc-100"
    >
      {{ label() }}
      <svg class="size-5" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M5.22 8.22a.75.75 0 0 1 1.06 0L10 11.94l3.72-3.72a.75.75 0 1 1 1.06 1.06l-4.25 4.25a.75.75 0 0 1-1.06 0L5.22 9.28a.75.75 0 0 1 0-1.06Z" />
      </svg>
    </button>
  `,
})
export class DropdownComponent {
  readonly label = input.required<string>();

  private readonly overlay = inject(Overlay);
  private readonly trigger = viewChild.required<ElementRef>('trigger');

  protected readonly isOpen = signal(false);
  private overlayRef: OverlayRef | null = null;

  protected toggle(): void {
    this.isOpen() ? this.close() : this.open();
  }

  private open(): void {
    const positionStrategy = this.overlay
      .position()
      .flexibleConnectedTo(this.trigger())
      .withPositions(DROPDOWN_POSITIONS);

    this.overlayRef = this.overlay.create({
      positionStrategy,
      scrollStrategy: this.overlay.scrollStrategies.reposition(),
      hasBackdrop: true,
      backdropClass: 'cdk-overlay-transparent-backdrop',
    });

    // 點擊背景關閉
    this.overlayRef.backdropClick().subscribe(() => this.close());

    // ESC 鍵關閉
    this.overlayRef.keydownEvents()
      .pipe(filter((e: KeyboardEvent) => e.key === 'Escape'))
      .subscribe(() => this.close());

    const portal = new ComponentPortal(DropdownPanelComponent);
    this.overlayRef.attach(portal);
    this.isOpen.set(true);
  }

  private close(): void {
    this.overlayRef?.dispose();
    this.overlayRef = null;
    this.isOpen.set(false);
  }
}

// 預設定位策略
const DROPDOWN_POSITIONS: ConnectedPosition[] = [
  { originX: 'start', originY: 'bottom', overlayX: 'start', overlayY: 'top', offsetY: 4 },
  { originX: 'start', originY: 'top', overlayX: 'start', overlayY: 'bottom', offsetY: -4 },
  { originX: 'end', originY: 'bottom', overlayX: 'end', overlayY: 'top', offsetY: 4 },
  { originX: 'end', originY: 'top', overlayX: 'end', overlayY: 'bottom', offsetY: -4 },
];
```

### Tooltip 定位模式

```typescript
const TOOLTIP_POSITIONS: ConnectedPosition[] = [
  // 上方（預設）
  { originX: 'center', originY: 'top', overlayX: 'center', overlayY: 'bottom', offsetY: -8 },
  // 下方（fallback）
  { originX: 'center', originY: 'bottom', overlayX: 'center', overlayY: 'top', offsetY: 8 },
  // 左方
  { originX: 'start', originY: 'center', overlayX: 'end', overlayY: 'center', offsetX: -8 },
  // 右方
  { originX: 'end', originY: 'center', overlayX: 'start', overlayY: 'center', offsetX: 8 },
];
```

## CDK A11y 模式

### FocusTrap（Dialog / Modal 必用）

```typescript
import { A11yModule, FocusTrapFactory } from '@angular/cdk/a11y';

@Component({
  standalone: true,
  imports: [A11yModule],
  template: `
    <div cdkTrapFocus [cdkTrapFocusAutoCapture]="true"
         data-testid="dialog-content">
      <h2>Dialog 標題</h2>
      <input data-testid="dialog-input" />
      <button data-testid="dialog-close" (click)="close()">關閉</button>
    </div>
  `,
})
export class DialogContentComponent {
  readonly close = output<void>();
}
```

### FocusMonitor（焦點狀態追蹤）

```typescript
import { FocusMonitor, FocusOrigin } from '@angular/cdk/a11y';

@Component({
  standalone: true,
  template: `
    <button #myButton
            [class.focused-keyboard]="focusOrigin() === 'keyboard'"
            [class.focused-mouse]="focusOrigin() === 'mouse'">
      按鈕
    </button>
  `,
})
export class FocusAwareButtonComponent implements OnDestroy {
  private readonly focusMonitor = inject(FocusMonitor);
  private readonly button = viewChild.required<ElementRef>('myButton');

  protected readonly focusOrigin = signal<FocusOrigin | null>(null);

  constructor() {
    afterNextRender(() => {
      this.focusMonitor.monitor(this.button()).subscribe((origin) => {
        this.focusOrigin.set(origin);
      });
    });
  }

  ngOnDestroy(): void {
    this.focusMonitor.stopMonitoring(this.button());
  }
}
```

### ListKeyManager（鍵盤導航列表）

```typescript
import { ActiveDescendantKeyManager } from '@angular/cdk/a11y';
import { Highlightable } from '@angular/cdk/a11y';

// 列表項目需實作 Highlightable
@Component({
  selector: 'app-list-item',
  standalone: true,
  template: `
    <li [class.active]="isActive"
        [attr.aria-selected]="isActive"
        role="option">
      <ng-content />
    </li>
  `,
})
export class ListItemComponent implements Highlightable {
  isActive = false;
  readonly disabled = input(false);

  setActiveStyles(): void {
    this.isActive = true;
  }

  setInactiveStyles(): void {
    this.isActive = false;
  }
}

// 父元件中使用 KeyManager
@Component({
  template: `
    <ul role="listbox"
        (keydown)="onKeydown($event)"
        data-testid="keyboard-list">
      @for (item of items(); track item.id) {
        <app-list-item>{{ item.name }}</app-list-item>
      }
    </ul>
  `,
})
export class KeyboardListComponent implements AfterViewInit {
  private readonly listItems = viewChildren(ListItemComponent);
  private keyManager!: ActiveDescendantKeyManager<ListItemComponent>;

  ngAfterViewInit(): void {
    this.keyManager = new ActiveDescendantKeyManager(this.listItems())
      .withWrap()
      .withHomeAndEnd()
      .withTypeAhead();
  }

  protected onKeydown(event: KeyboardEvent): void {
    this.keyManager.onKeydown(event);
  }
}
```

### LiveAnnouncer（螢幕閱讀器通知）

```typescript
import { LiveAnnouncer } from '@angular/cdk/a11y';

@Injectable({ providedIn: 'root' })
export class NotificationService {
  private readonly liveAnnouncer = inject(LiveAnnouncer);

  announceSuccess(message: string): void {
    this.liveAnnouncer.announce(message, 'polite');
  }

  announceError(message: string): void {
    this.liveAnnouncer.announce(message, 'assertive');
  }
}
```

## CDK Dialog（無頭 Dialog 系統）

```typescript
import { Dialog, DialogRef, DIALOG_DATA, DialogModule } from '@angular/cdk/dialog';

@Injectable({ providedIn: 'root' })
export class DialogService {
  private readonly dialog = inject(Dialog);

  open<T, R = unknown>(
    component: ComponentType<T>,
    config?: { data?: unknown; width?: string }
  ): DialogRef<R, T> {
    return this.dialog.open(component, {
      data: config?.data,
      width: config?.width ?? '28rem',
      panelClass: [
        'rounded-lg',
        'bg-white',
        'dark:bg-zinc-900',
        'shadow-lg',
        'ring-1',
        'ring-zinc-950/10',
        'dark:ring-white/10',
      ],
      backdropClass: 'bg-zinc-950/25',
      ariaModal: true,
      autoFocus: true,
      restoreFocus: true,
    });
  }
}
```

## CDK Virtual Scrolling

```typescript
import { ScrollingModule, CdkVirtualScrollViewport } from '@angular/cdk/scrolling';

@Component({
  standalone: true,
  imports: [ScrollingModule],
  template: `
    <cdk-virtual-scroll-viewport
      [itemSize]="ITEM_HEIGHT_PX"
      class="h-96 w-full"
      data-testid="virtual-list">
      <div *cdkVirtualFor="let item of items(); trackBy: trackById"
           class="flex items-center px-4 border-b border-zinc-200 dark:border-zinc-800"
           [style.height.px]="ITEM_HEIGHT_PX">
        {{ item.name }}
      </div>
    </cdk-virtual-scroll-viewport>
  `,
})
export class VirtualListComponent {
  readonly items = input.required<Item[]>();

  protected readonly ITEM_HEIGHT_PX = 48;

  protected trackById(_index: number, item: Item): string {
    return item.id;
  }
}
```

## CDK DragDrop

```typescript
import { DragDropModule, CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';

@Component({
  standalone: true,
  imports: [DragDropModule],
  template: `
    <div cdkDropList
         (cdkDropListDropped)="drop($event)"
         class="space-y-2"
         data-testid="sortable-list">
      @for (item of items(); track item.id) {
        <div cdkDrag
             class="flex items-center gap-3 rounded-lg bg-white p-3 shadow-xs dark:bg-zinc-800"
             [attr.data-testid]="'drag-item-' + item.id">
          <svg cdkDragHandle class="size-5 cursor-grab text-zinc-400">...</svg>
          {{ item.name }}
        </div>
      }
    </div>
  `,
})
export class SortableListComponent {
  readonly items = model.required<Item[]>();

  protected drop(event: CdkDragDrop<Item[]>): void {
    const updated = [...this.items()];
    moveItemInArray(updated, event.previousIndex, event.currentIndex);
    this.items.set(updated);
  }
}
```

## CDK Layout（BreakpointObserver）

```typescript
import { BreakpointObserver, Breakpoints } from '@angular/cdk/layout';

@Injectable({ providedIn: 'root' })
export class ResponsiveService {
  private readonly breakpointObserver = inject(BreakpointObserver);

  // 使用自訂 Tailwind 斷點
  readonly isMobile = toSignal(
    this.breakpointObserver.observe('(max-width: 639px)')
      .pipe(map(result => result.matches)),
    { initialValue: false }
  );

  readonly isTablet = toSignal(
    this.breakpointObserver.observe('(min-width: 640px) and (max-width: 1023px)')
      .pipe(map(result => result.matches)),
    { initialValue: false }
  );

  readonly isDesktop = toSignal(
    this.breakpointObserver.observe('(min-width: 1024px)')
      .pipe(map(result => result.matches)),
    { initialValue: false }
  );
}
```

## CDK Clipboard

```typescript
import { ClipboardModule, Clipboard } from '@angular/cdk/clipboard';

@Component({
  standalone: true,
  imports: [ClipboardModule],
  template: `
    <button (click)="copyToClipboard()"
            data-testid="copy-button"
            class="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200">
      @if (copied()) {
        <svg class="size-4 text-emerald-500">...</svg>
        已複製
      } @else {
        <svg class="size-4">...</svg>
        複製
      }
    </button>
  `,
})
export class CopyButtonComponent {
  readonly text = input.required<string>();

  private readonly clipboard = inject(Clipboard);
  protected readonly copied = signal(false);

  protected copyToClipboard(): void {
    this.clipboard.copy(this.text());
    this.copied.set(true);
    setTimeout(() => this.copied.set(false), 2000);
  }
}
```

## CDK TextField（Auto-size Textarea）

```typescript
import { TextFieldModule } from '@angular/cdk/text-field';

@Component({
  standalone: true,
  imports: [TextFieldModule],
  template: `
    <textarea
      cdkTextareaAutosize
      [cdkAutosizeMinRows]="3"
      [cdkAutosizeMaxRows]="10"
      data-testid="auto-textarea"
      class="block w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
    ></textarea>
  `,
})
export class AutoTextareaComponent {}
```

## 測試指引

### Overlay 測試

```typescript
import { OverlayContainer } from '@angular/cdk/overlay';

describe('DropdownComponent', () => {
  let overlayContainer: OverlayContainer;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [DropdownComponent],
    });
    overlayContainer = TestBed.inject(OverlayContainer);
  });

  afterEach(() => {
    overlayContainer.ngOnDestroy();
  });

  it('should open overlay when trigger is clicked', () => {
    const trigger = fixture.nativeElement.querySelector('[data-testid="dropdown-trigger"]');
    trigger.click();
    fixture.detectChanges();

    const panel = overlayContainer.getContainerElement()
      .querySelector('[data-testid="dropdown-panel"]');
    expect(panel).toBeTruthy();
  });

  it('should close overlay when ESC is pressed', () => {
    // open first
    trigger.click();
    fixture.detectChanges();

    // press ESC
    const event = new KeyboardEvent('keydown', { key: 'Escape' });
    document.dispatchEvent(event);
    fixture.detectChanges();

    const panel = overlayContainer.getContainerElement()
      .querySelector('[data-testid="dropdown-panel"]');
    expect(panel).toBeNull();
  });
});
```

### FocusTrap 測試

```typescript
it('should trap focus inside dialog', () => {
  // Open dialog
  dialogService.open(TestDialogComponent);
  fixture.detectChanges();

  const dialogContent = overlayContainer.getContainerElement()
    .querySelector('[data-testid="dialog-content"]');
  expect(dialogContent).toBeTruthy();

  // Tab 鍵應該在 dialog 內循環
  const focusableElements = dialogContent!.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  expect(focusableElements.length).toBeGreaterThan(0);
});
```

## 檢查清單

- [ ] 使用具體路徑匯入 CDK 模組（`@angular/cdk/overlay`，非 `@angular/cdk`）
- [ ] Overlay 設定 `hasBackdrop` + 背景點擊關閉
- [ ] Overlay 設定 ESC 鍵關閉
- [ ] Dialog 使用 `cdkTrapFocus` + `cdkTrapFocusAutoCapture`
- [ ] Dialog 設定 `restoreFocus: true`
- [ ] 列表鍵盤導航使用 `ActiveDescendantKeyManager` 或 `FocusKeyManager`
- [ ] 虛擬捲動設定固定 `itemSize`
- [ ] 狀態變更通知螢幕閱讀器（`LiveAnnouncer`）
- [ ] 測試使用 `OverlayContainer` 查詢浮層內容
- [ ] `afterEach` 清理 `overlayContainer.ngOnDestroy()`

## 參考資源

- [Angular CDK Documentation](https://material.angular.io/cdk/categories) — CDK 模組完整文件
- [CDK Overlay](https://material.angular.io/cdk/overlay/overview) — Overlay 定位系統
- [CDK A11y](https://material.angular.io/cdk/a11y/overview) — 無障礙工具
- [CDK Scrolling](https://material.angular.io/cdk/scrolling/overview) — 虛擬捲動
- [CDK Drag and Drop](https://material.angular.io/cdk/drag-drop/overview) — 拖放系統
- [CDK Dialog](https://material.angular.io/cdk/dialog/overview) — 無頭 Dialog


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [ui-components](../angular-rules/references/ui-components.md) — 三層 UI 元件策略與 CDK 使用指引
- [angular-conventions](../angular-rules/references/angular-conventions.md) — Standalone、Signal 等強制性 API
