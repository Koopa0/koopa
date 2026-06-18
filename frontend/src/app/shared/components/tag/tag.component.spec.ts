import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TagComponent } from './tag.component';

// ---------------------------------------------------------------------------
// Host component for content-projection tests
// ---------------------------------------------------------------------------
@Component({
  imports: [TagComponent],
  template: `<app-tag [href]="href()" [testId]="testId()">{{
    label()
  }}</app-tag>`,
})
class HostComponent {
  readonly href = signal<string | null>(null);
  readonly testId = signal<string | null>(null);
  readonly label = signal('#angular');
}

describe('TagComponent', () => {
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

  function anchor(): HTMLAnchorElement {
    return fixture.nativeElement.querySelector('a') as HTMLAnchorElement;
  }

  it('should create', () => {
    expect(host).toBeTruthy();
  });

  it('should project label text into the tag', () => {
    expect(anchor().textContent).toContain('#angular');
  });

  describe('href input', () => {
    it('should not set href attribute when href is null', async () => {
      host.href.set(null);
      await fixture.whenStable();
      // Angular sets attr to null — the attribute should be absent
      expect(anchor().getAttribute('href')).toBeNull();
    });

    it('should set href attribute when href is provided', async () => {
      host.href.set('/tags/angular');
      await fixture.whenStable();
      expect(anchor().getAttribute('href')).toBe('/tags/angular');
    });

    it('should always render an <a> element regardless of href', async () => {
      // The template always uses <a> — verify the element type
      host.href.set(null);
      await fixture.whenStable();
      expect(anchor()).toBeTruthy();
      expect(anchor().tagName).toBe('A');
    });
  });

  describe('testId input', () => {
    it('should not set data-testid when testId is null', async () => {
      host.testId.set(null);
      await fixture.whenStable();
      expect(anchor().getAttribute('data-testid')).toBeNull();
    });

    it('should set data-testid attribute when testId is provided', async () => {
      host.testId.set('tag-angular');
      await fixture.whenStable();
      expect(anchor().getAttribute('data-testid')).toBe('tag-angular');
    });
  });

  describe('label content', () => {
    it('should display updated label when projected content changes', async () => {
      host.label.set('#vitest');
      await fixture.whenStable();
      expect(anchor().textContent).toContain('#vitest');
    });
  });
});
