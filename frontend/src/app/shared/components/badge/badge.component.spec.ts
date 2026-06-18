import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BadgeComponent, type BadgeTone } from './badge.component';

@Component({
  imports: [BadgeComponent],
  template: `<app-badge [tone]="tone()" [testId]="testId()">{{
    label()
  }}</app-badge>`,
})
class HostComponent {
  readonly tone = signal<BadgeTone>('neutral');
  readonly testId = signal<string | null>(null);
  readonly label = signal('Draft');
}

describe('BadgeComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;

  function spanEl(): HTMLSpanElement {
    return fixture.nativeElement.querySelector('span') as HTMLSpanElement;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostComponent],
    }).compileComponents();
    fixture = TestBed.createComponent(HostComponent);
    host = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(spanEl()).toBeTruthy();
  });

  it('should project label text into the badge', async () => {
    host.label.set('Published');
    await fixture.whenStable();
    expect(spanEl().textContent?.trim()).toBe('Published');
  });

  it('should forward testId to data-testid attribute when provided', async () => {
    host.testId.set('status-badge');
    await fixture.whenStable();
    expect(spanEl().getAttribute('data-testid')).toBe('status-badge');
  });

  it('should have no data-testid attribute when testId is null', async () => {
    await fixture.whenStable();
    expect(spanEl().getAttribute('data-testid')).toBeNull();
  });

  it('should apply neutral tone classes when tone is neutral', async () => {
    await fixture.whenStable();
    expect(spanEl().className).toContain('bg-elevated');
    expect(spanEl().className).toContain('text-fg-muted');
  });

  it('should apply success tone classes when tone is success', async () => {
    host.tone.set('success');
    await fixture.whenStable();
    expect(spanEl().className).toContain('bg-success-bg');
    expect(spanEl().className).toContain('text-success');
  });

  it('should apply error tone classes when tone is error', async () => {
    host.tone.set('error');
    await fixture.whenStable();
    expect(spanEl().className).toContain('bg-error-bg');
    expect(spanEl().className).toContain('text-error');
  });

  it('should apply warn tone classes when tone is warn', async () => {
    host.tone.set('warn');
    await fixture.whenStable();
    expect(spanEl().className).toContain('bg-warn-bg');
    expect(spanEl().className).toContain('text-warn');
  });

  it('should apply brand tone classes when tone is brand', async () => {
    host.tone.set('brand');
    await fixture.whenStable();
    expect(spanEl().className).toContain('bg-brand-muted');
    expect(spanEl().className).toContain('text-brand-strong');
  });

  it('should apply info tone classes when tone is info', async () => {
    host.tone.set('info');
    await fixture.whenStable();
    expect(spanEl().className).toContain('bg-info-bg');
    expect(spanEl().className).toContain('text-info');
  });

  it('should always include base layout classes regardless of tone', async () => {
    host.tone.set('success');
    await fixture.whenStable();
    expect(spanEl().className).toContain('inline-flex');
    expect(spanEl().className).toContain('rounded-sm');
  });

  it('should update displayed text when label changes', async () => {
    host.label.set('Active');
    await fixture.whenStable();
    expect(spanEl().textContent?.trim()).toBe('Active');

    host.label.set('Inactive');
    await fixture.whenStable();
    expect(spanEl().textContent?.trim()).toBe('Inactive');
  });
});
