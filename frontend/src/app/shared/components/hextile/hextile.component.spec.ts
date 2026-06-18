import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HextileComponent } from './hextile.component';

@Component({
  standalone: true,
  imports: [HextileComponent],
  template: `
    <app-hextile [testId]="testId()">
      <svg data-testid="projected-icon" aria-hidden="true"><path /></svg>
    </app-hextile>
  `,
})
class HextileHostComponent {
  readonly testId = signal<string | null>(null);
}

describe('HextileComponent', () => {
  let fixture: ComponentFixture<HextileHostComponent>;
  let host: HextileHostComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HextileHostComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(HextileHostComponent);
    host = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(host).toBeTruthy();
  });

  describe('aria-hidden', () => {
    it('should be aria-hidden true so decorative tile is skipped by screen readers', () => {
      const span = fixture.nativeElement.querySelector(
        'app-hextile span',
      ) as HTMLElement;
      expect(span.getAttribute('aria-hidden')).toBe('true');
    });
  });

  describe('content projection', () => {
    it('should render projected icon content inside the tile', () => {
      const icon = fixture.nativeElement.querySelector(
        '[data-testid="projected-icon"]',
      );
      expect(icon).toBeTruthy();
    });
  });

  describe('shape classes', () => {
    it('should have rounded-md class for the tile container', () => {
      const span = fixture.nativeElement.querySelector(
        'app-hextile span',
      ) as HTMLElement;
      expect(span.className).toContain('rounded-md');
    });

    it('should have size-10 class making it a fixed square tile', () => {
      const span = fixture.nativeElement.querySelector(
        'app-hextile span',
      ) as HTMLElement;
      expect(span.className).toContain('size-10');
    });

    it('should have brand-muted background class', () => {
      const span = fixture.nativeElement.querySelector(
        'app-hextile span',
      ) as HTMLElement;
      expect(span.className).toContain('bg-brand-muted');
    });

    it('should have brand-strong text colour for AA-safe icon contrast', () => {
      const span = fixture.nativeElement.querySelector(
        'app-hextile span',
      ) as HTMLElement;
      expect(span.className).toContain('text-brand-strong');
    });
  });

  describe('testId', () => {
    it('should set data-testid when testId input is provided', async () => {
      host.testId.set('feature-tile');
      await fixture.whenStable();

      const el = fixture.nativeElement.querySelector(
        '[data-testid="feature-tile"]',
      );
      expect(el).toBeTruthy();
    });

    it('should not render data-testid when testId is null', async () => {
      host.testId.set(null);
      await fixture.whenStable();

      const span = fixture.nativeElement.querySelector(
        'app-hextile span[data-testid]',
      );
      expect(span).toBeNull();
    });
  });
});
