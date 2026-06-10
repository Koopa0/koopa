import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import {
  DashboardWidgetComponent,
  type WidgetState,
} from './dashboard-widget.component';

// Host wraps the widget so projected content behaves exactly as the
// dashboard page uses it: body markup only renders in the ok state.
@Component({
  standalone: true,
  imports: [DashboardWidgetComponent],
  template: `
    <app-dashboard-widget
      title="Concepts"
      meta="12 tracked"
      [state]="state"
      testId="concepts"
      (retry)="retries = retries + 1"
    >
      <p data-testid="projected-body">widget body</p>
    </app-dashboard-widget>
  `,
})
class HostComponent {
  state: WidgetState = 'loading';
  retries = 0;
}

describe('DashboardWidgetComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;

  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [HostComponent] });
    fixture = TestBed.createComponent(HostComponent);
    host = fixture.componentInstance;
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  it('should render skeleton lines and a loading meta when state is loading', () => {
    fixture.detectChanges();

    expect(
      el().querySelector('[data-testid="widget-concepts-loading"]'),
    ).toBeTruthy();
    expect(el().textContent).toContain('loading…');
    expect(el().querySelector('[data-testid="projected-body"]')).toBeNull();
  });

  it('should render title, meta, and projected content when state is ok', () => {
    host.state = 'ok';
    fixture.detectChanges();

    expect(el().textContent).toContain('Concepts');
    expect(el().textContent).toContain('12 tracked');
    expect(el().querySelector('[data-testid="projected-body"]')).toBeTruthy();
    expect(
      el().querySelector('[data-testid="widget-concepts-error"]'),
    ).toBeNull();
  });

  it('should render the inline error with a Retry button when state is error', () => {
    host.state = 'error';
    fixture.detectChanges();

    const error = el().querySelector('[data-testid="widget-concepts-error"]');
    expect(error).toBeTruthy();
    expect(error?.textContent).toContain("Couldn't load this widget");
    expect(error?.textContent).toContain(
      'The rest of the dashboard is unaffected',
    );
    expect(el().querySelector('[data-testid="projected-body"]')).toBeNull();
  });

  it('should emit retry when the Retry button is clicked', () => {
    host.state = 'error';
    fixture.detectChanges();

    const retry = el().querySelector<HTMLButtonElement>(
      '[data-testid="widget-concepts-retry"]',
    );
    retry?.click();
    fixture.detectChanges();

    expect(host.retries).toBe(1);
  });

  it('should render the empty state copy when state is empty', () => {
    host.state = 'empty';
    fixture.detectChanges();

    const empty = el().querySelector('[data-testid="widget-concepts-empty"]');
    expect(empty).toBeTruthy();
    expect(empty?.textContent).toContain('Nothing here yet');
    expect(empty?.textContent).toContain("Come back once there's signal.");
    expect(el().querySelector('[data-testid="projected-body"]')).toBeNull();
  });
});
