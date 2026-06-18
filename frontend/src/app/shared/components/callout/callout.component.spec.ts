import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CalloutComponent, type CalloutVariant } from './callout.component';

@Component({
  template: `
    <app-callout [variant]="variant()" [label]="label()" [testId]="testId()">
      {{ body() }}
    </app-callout>
  `,
  imports: [CalloutComponent],
})
class HostComponent {
  readonly variant = signal<CalloutVariant>('brand');
  readonly label = signal<string | null>(null);
  readonly testId = signal<string | null>(null);
  readonly body = signal('Callout body text.');
}

describe('CalloutComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;

  function containerEl(): HTMLElement {
    return fixture.nativeElement.querySelector('div') as HTMLElement;
  }

  function labelEl(): HTMLElement | null {
    return fixture.nativeElement.querySelector(
      'div > div:first-child',
    ) as HTMLElement | null;
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
    expect(containerEl()).toBeTruthy();
  });

  it('should project body text into the content area', async () => {
    host.body.set('Important note here.');
    await fixture.whenStable();
    expect(containerEl().textContent).toContain('Important note here.');
  });

  it('should not render label element when label input is null', async () => {
    host.label.set(null);
    await fixture.whenStable();
    const children = containerEl().querySelectorAll('div');
    const hasUppercaseLabel = Array.from(children).some((el) =>
      el.className.includes('uppercase'),
    );
    expect(hasUppercaseLabel).toBe(false);
  });

  it('should render label text when label input is provided', async () => {
    host.label.set('Note');
    await fixture.whenStable();
    const el = labelEl();
    expect(el).toBeTruthy();
    expect(el?.textContent?.trim()).toBe('Note');
  });

  it('should forward testId to data-testid attribute when provided', async () => {
    host.testId.set('my-callout');
    await fixture.whenStable();
    expect(containerEl().getAttribute('data-testid')).toBe('my-callout');
  });

  it('should have no data-testid when testId is null', async () => {
    await fixture.whenStable();
    expect(containerEl().getAttribute('data-testid')).toBeNull();
  });

  it('should apply brand left-border class when variant is brand', async () => {
    host.variant.set('brand');
    await fixture.whenStable();
    expect(containerEl().className).toContain('border-l-brand');
  });

  it('should apply warn left-border class when variant is warn', async () => {
    host.variant.set('warn');
    await fixture.whenStable();
    expect(containerEl().className).toContain('border-l-warn');
  });

  it('should apply success left-border class when variant is success', async () => {
    host.variant.set('success');
    await fixture.whenStable();
    expect(containerEl().className).toContain('border-l-success');
  });

  it('should apply error left-border class when variant is error', async () => {
    host.variant.set('error');
    await fixture.whenStable();
    expect(containerEl().className).toContain('border-l-error');
  });

  it('should apply note left-border class when variant is note', async () => {
    host.variant.set('note');
    await fixture.whenStable();
    expect(containerEl().className).toContain('border-l-fg-subtle');
  });

  it('should apply brand label colour class when variant is brand and label is set', async () => {
    host.variant.set('brand');
    host.label.set('Tip');
    await fixture.whenStable();
    const el = labelEl();
    expect(el?.className).toContain('text-brand');
  });

  it('should apply error label colour class when variant is error and label is set', async () => {
    host.variant.set('error');
    host.label.set('Error');
    await fixture.whenStable();
    const el = labelEl();
    expect(el?.className).toContain('text-error');
  });

  it('should always include base structural classes on the container', async () => {
    await fixture.whenStable();
    expect(containerEl().className).toContain('rounded-r-md');
    expect(containerEl().className).toContain('bg-panel');
  });
});
