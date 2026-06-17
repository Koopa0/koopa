import { Component, input } from '@angular/core';
import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { TodaySessionCardComponent } from './session-card.component';
import type { ActiveSession } from './today.service';

function session(): ActiveSession {
  return {
    id: 's1',
    domain: 'system-design',
    mode: 'reading',
    started_at: '2026-06-07T09:00:00Z',
    created_at: '2026-06-07T09:00:00Z',
  };
}

@Component({
  imports: [TodaySessionCardComponent],
  template: `<app-today-session-card [session]="session()" />`,
})
class HostComponent {
  readonly session = input.required<ActiveSession>();
}

describe('TodaySessionCardComponent', () => {
  let fixture: ComponentFixture<HostComponent>;

  function render(value: ActiveSession): HTMLElement {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    fixture = TestBed.createComponent(HostComponent);
    fixture.componentRef.setInput('session', value);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('should render domain and mode when a session is open', () => {
    const el = render(session());
    const card = el.querySelector('[data-testid="today-session"]');
    expect(card?.textContent).toContain('system-design');
    expect(card?.textContent).toContain('reading');
  });

  it('should render an hh:mm:ss elapsed figure', () => {
    const el = render(session());
    const elapsed = el.querySelector(
      '[data-testid="today-session-elapsed"]',
    )?.textContent;
    expect(elapsed?.trim()).toMatch(/^\d{2,}:\d{2}:\d{2}$/);
  });

  it('should link into the session timeline when clicked', () => {
    const el = render(session());
    const link = el.querySelector<HTMLAnchorElement>('a[href]');
    expect(link?.getAttribute('href')).toBe('/admin/learning/sessions/s1');
  });
});
