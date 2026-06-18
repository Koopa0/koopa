import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { KbdComponent } from './kbd.component';

// ---------------------------------------------------------------------------
// Host component for content-projection tests
// ---------------------------------------------------------------------------
@Component({
  imports: [KbdComponent],
  template: `<app-kbd [testId]="testId()">{{ key() }}</app-kbd>`,
})
class HostComponent {
  readonly testId = signal<string | null>(null);
  readonly key = signal('⌘K');
}

describe('KbdComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(HostComponent);
    host = fixture.componentInstance;
    await fixture.whenStable();
  });

  function kbdEl(): HTMLElement {
    return fixture.nativeElement.querySelector('kbd') as HTMLElement;
  }

  it('should create', () => {
    expect(host).toBeTruthy();
  });

  it('should render a <kbd> element', () => {
    expect(kbdEl()).toBeTruthy();
    expect(kbdEl().tagName).toBe('KBD');
  });

  it('should project key glyph text into the kbd element', () => {
    expect(kbdEl().textContent).toContain('⌘K');
  });

  describe('testId input', () => {
    it('should not set data-testid when testId is null', async () => {
      host.testId.set(null);
      await fixture.whenStable();
      expect(kbdEl().getAttribute('data-testid')).toBeNull();
    });

    it('should set data-testid attribute when testId is provided', async () => {
      host.testId.set('shortcut-search');
      await fixture.whenStable();
      expect(kbdEl().getAttribute('data-testid')).toBe('shortcut-search');
    });
  });

  describe('projected content', () => {
    it('should display updated key label when projected content changes', async () => {
      host.key.set('Esc');
      await fixture.whenStable();
      expect(kbdEl().textContent).toContain('Esc');
    });

    it('should display multi-key label when projected', async () => {
      host.key.set('Ctrl+Shift+P');
      await fixture.whenStable();
      expect(kbdEl().textContent).toContain('Ctrl+Shift+P');
    });
  });
});
