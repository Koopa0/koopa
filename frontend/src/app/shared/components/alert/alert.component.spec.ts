import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { AlertComponent, type AlertVariant } from './alert.component';

@Component({
  template: `
    <app-alert [variant]="variant()" [heading]="heading()" [testId]="testId()">
      <svg alert-icon data-testid="alert-icon-slot" aria-hidden="true"></svg>
      {{ message() }}
    </app-alert>
  `,
  imports: [AlertComponent],
})
class HostComponent {
  readonly variant = signal<AlertVariant>('info');
  readonly heading = signal<string | null>(null);
  readonly testId = signal<string | null>(null);
  readonly message = signal('Something happened.');
}

describe('AlertComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;

  function alertEl(): HTMLElement {
    return fixture.nativeElement.querySelector('[role="alert"]') as HTMLElement;
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
    expect(alertEl()).toBeTruthy();
  });

  it('should have role="alert" on the container', () => {
    expect(alertEl().getAttribute('role')).toBe('alert');
  });

  it('should project message text into the content area', async () => {
    host.message.set('File saved successfully.');
    await fixture.whenStable();
    expect(alertEl().textContent).toContain('File saved successfully.');
  });

  it('should project icon content into the alert-icon slot', () => {
    const icon = fixture.nativeElement.querySelector(
      '[data-testid="alert-icon-slot"]',
    );
    expect(icon).toBeTruthy();
  });

  it('should not render heading element when heading is null', async () => {
    host.heading.set(null);
    await fixture.whenStable();
    expect(alertEl().querySelector('strong')).toBeNull();
  });

  it('should render heading text when heading input is provided', async () => {
    host.heading.set('Warning');
    await fixture.whenStable();
    const strong = alertEl().querySelector('strong');
    expect(strong).toBeTruthy();
    expect(strong?.textContent?.trim()).toBe('Warning');
  });

  it('should forward testId to data-testid attribute when provided', async () => {
    host.testId.set('form-alert');
    await fixture.whenStable();
    expect(alertEl().getAttribute('data-testid')).toBe('form-alert');
  });

  it('should have no data-testid attribute when testId is null', async () => {
    await fixture.whenStable();
    expect(alertEl().getAttribute('data-testid')).toBeNull();
  });

  it('should apply info classes when variant is info', async () => {
    host.variant.set('info');
    await fixture.whenStable();
    expect(alertEl().className).toContain('bg-info-bg');
    expect(alertEl().className).toContain('text-info');
  });

  it('should apply success classes when variant is success', async () => {
    host.variant.set('success');
    await fixture.whenStable();
    expect(alertEl().className).toContain('bg-success-bg');
    expect(alertEl().className).toContain('text-success');
  });

  it('should apply warn classes when variant is warn', async () => {
    host.variant.set('warn');
    await fixture.whenStable();
    expect(alertEl().className).toContain('bg-warn-bg');
    expect(alertEl().className).toContain('text-warn');
  });

  it('should apply error classes when variant is error', async () => {
    host.variant.set('error');
    await fixture.whenStable();
    expect(alertEl().className).toContain('bg-error-bg');
    expect(alertEl().className).toContain('text-error');
  });

  it('should always include base layout classes regardless of variant', async () => {
    host.variant.set('warn');
    await fixture.whenStable();
    expect(alertEl().className).toContain('flex');
    expect(alertEl().className).toContain('rounded-sm');
  });

  it('should update heading text when heading input changes', async () => {
    host.heading.set('First');
    await fixture.whenStable();
    expect(alertEl().querySelector('strong')?.textContent?.trim()).toBe(
      'First',
    );

    host.heading.set('Second');
    await fixture.whenStable();
    expect(alertEl().querySelector('strong')?.textContent?.trim()).toBe(
      'Second',
    );
  });
});
