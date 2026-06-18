import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { OverlayContainer } from '@angular/cdk/overlay';
import {
  CommandPaletteComponent,
  type CommandItem,
} from './command-palette.component';

const ITEMS: CommandItem[] = [
  { id: 'new', label: 'New article', group: 'Create' },
  { id: 'search', label: 'Search', group: 'Navigate', meta: 'K' },
  { id: 'theme', label: 'Toggle theme', group: 'Settings' },
];

@Component({
  imports: [CommandPaletteComponent],
  template: `
    <app-command-palette
      [(open)]="open"
      [items]="items"
      (selected)="onSelected($event)"
    />
  `,
})
class HostComponent {
  readonly open = signal(false);
  readonly items = ITEMS;
  readonly selectedItem = signal<CommandItem | null>(null);
  onSelected(item: CommandItem): void {
    this.selectedItem.set(item);
  }
}

describe('CommandPaletteComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;
  let overlay: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostComponent],
    }).compileComponents();
    fixture = TestBed.createComponent(HostComponent);
    host = fixture.componentInstance;
    overlay = TestBed.inject(OverlayContainer).getContainerElement();
    await fixture.whenStable();
  });

  afterEach(() => {
    TestBed.inject(OverlayContainer).ngOnDestroy();
  });

  async function openPalette(): Promise<void> {
    host.open.set(true);
    fixture.detectChanges();
    await fixture.whenStable();
  }

  function panel(): HTMLElement | null {
    return overlay.querySelector('[role="dialog"]');
  }
  function options(): HTMLElement[] {
    return Array.from(overlay.querySelectorAll('[role="option"]'));
  }
  function searchInput(): HTMLInputElement {
    return overlay.querySelector('[data-testid="command-palette-input"]')!;
  }

  it('should not render the panel while closed', () => {
    expect(panel()).toBeNull();
  });

  it('should render the panel and all items when opened', async () => {
    await openPalette();
    expect(panel()).not.toBeNull();
    expect(options()).toHaveLength(3);
  });

  it('should filter items by the search query', async () => {
    await openPalette();
    const input = searchInput();
    input.value = 'theme';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    await fixture.whenStable();
    const labels = options().map((o) => o.textContent?.trim());
    expect(options()).toHaveLength(1);
    expect(labels[0]).toContain('Toggle theme');
  });

  it('should mark the first item active on open via aria-selected', async () => {
    await openPalette();
    expect(options()[0].getAttribute('aria-selected')).toBe('true');
  });

  it('should move the active item with ArrowDown', async () => {
    await openPalette();
    panel()!.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }),
    );
    fixture.detectChanges();
    await fixture.whenStable();
    expect(options()[1].getAttribute('aria-selected')).toBe('true');
  });

  it('should emit the selected item and close on Enter', async () => {
    await openPalette();
    panel()!.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }),
    );
    fixture.detectChanges();
    await fixture.whenStable();
    expect(host.selectedItem()?.id).toBe('new');
    expect(host.open()).toBe(false);
  });

  it('should emit the clicked item', async () => {
    await openPalette();
    overlay
      .querySelector<HTMLElement>('[data-testid="command-option-theme"]')!
      .click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(host.selectedItem()?.id).toBe('theme');
  });

  it('should close on Escape without selecting', async () => {
    await openPalette();
    panel()!.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }),
    );
    fixture.detectChanges();
    await fixture.whenStable();
    expect(host.open()).toBe(false);
    expect(host.selectedItem()).toBeNull();
  });

  it('should show the empty state when nothing matches', async () => {
    await openPalette();
    const input = searchInput();
    input.value = 'zzzznomatch';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    await fixture.whenStable();
    expect(options()).toHaveLength(0);
    expect(panel()!.textContent).toContain('No results found');
  });
});
