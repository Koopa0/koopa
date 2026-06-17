import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';
import { AgentInspectorComponent } from './agent-inspector.component';
import type { Agent } from '../../../../core/models/workbench.model';

const baseAgent: Agent = {
  name: 'planner',
  display_name: 'Planner',
  platform: 'claude-cowork',
  description: 'Daily planner — morning briefing and candidate day plan',
  schedule: {
    name: 'morning-briefing',
    trigger: 'cron',
    expr: '0 8 * * *',
    backend: 'cowork_desktop',
    purpose: 'Daily briefing — todos, projects, goals, RSS highlights',
  },
  status: 'active',
};

describe('AgentInspectorComponent', () => {
  let fixture: ComponentFixture<AgentInspectorComponent>;
  let httpMock: HttpTestingController;

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideNoopAnimations(),
        provideRouter([]),
      ],
    });
    fixture = TestBed.createComponent(AgentInspectorComponent);
    httpMock = TestBed.inject(HttpTestingController);
  }

  function flushAll(name: string, response: Agent | null): void {
    const reqs = httpMock.match((r) =>
      r.url.includes(`/api/admin/system/agents/${name}`),
    );
    expect(reqs.length).toBeGreaterThan(0);
    for (const r of reqs) {
      if (response === null) {
        r.flush(null, { status: 500, statusText: 'Internal Server Error' });
      } else {
        r.flush({ data: response });
      }
    }
  }

  async function loadAndSettle(a: Agent | null): Promise<void> {
    fixture.componentRef.setInput('id', baseAgent.name);
    fixture.detectChanges();
    flushAll(baseAgent.name, a);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should render display_name + name + platform subtitle', async () => {
    setupFixture();
    await loadAndSettle(baseAgent);

    const el = fixture.nativeElement as HTMLElement;
    expect(
      el.querySelector('[data-testid="agent-display-name"]')?.textContent,
    ).toContain('Planner');
    const subtitle = el.querySelector('[data-testid="agent-subtitle"]');
    expect(subtitle?.textContent).toContain('planner');
    expect(subtitle?.textContent).toContain('claude-cowork');
  });

  it('should render schedule as its purpose, NOT the cron literal in default view', async () => {
    setupFixture();
    await loadAndSettle(baseAgent);

    const sched = fixture.nativeElement.querySelector(
      '[data-testid="agent-schedule"]',
    );
    expect(sched?.textContent?.trim()).toBe(
      'Daily briefing — todos, projects, goals, RSS highlights',
    );
    expect(sched?.textContent).not.toContain('0 8 * * *');
  });

  it('should omit the schedule row for an agent without a schedule', async () => {
    setupFixture();
    await loadAndSettle({
      name: 'koopa0-dev',
      display_name: 'koopa',
      platform: 'claude-code',
      description: 'koopa development project',
      status: 'active',
    });

    const sched = fixture.nativeElement.querySelector(
      '[data-testid="agent-schedule"]',
    );
    expect(sched).toBeFalsy();
  });

  it('should not render any retired capability UI', async () => {
    setupFixture();
    await loadAndSettle(baseAgent);

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="agent-capabilities"]')).toBeFalsy();
    expect(el.querySelector('[data-testid="agent-open-tasks-link"]')).toBeFalsy();
    expect(el.querySelector('[data-testid="agent-no-open-tasks"]')).toBeFalsy();
    expect(el.textContent).not.toContain('submits tasks');
  });

  it('should expose cron expression in <details> progressive disclosure', async () => {
    setupFixture();
    await loadAndSettle(baseAgent);

    const details = fixture.nativeElement.querySelector(
      '[data-testid="agent-cron-details"]',
    );
    expect(details).toBeTruthy();
    expect(details?.tagName.toLowerCase()).toBe('details');
    expect(details?.textContent).toContain('0 8 * * *');
    expect(details?.textContent).toContain('cowork_desktop');
  });

  it('should render system agent warning for the system fallback identity', async () => {
    setupFixture();
    await loadAndSettle({
      name: 'system',
      display_name: 'System',
      platform: 'system',
      description:
        'Database-level writes without Go caller context — pg_cron jobs',
      status: 'active',
    });

    const warning = fixture.nativeElement.querySelector(
      '[data-testid="agent-system-warning"]',
    );
    expect(warning).toBeTruthy();
    expect(warning?.textContent).toContain('fallback identity');
  });

  it('should render retired status with line-through title', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseAgent,
      status: 'retired',
    });

    const title = fixture.nativeElement.querySelector(
      '[data-testid="agent-display-name"]',
    );
    expect(title?.classList.contains('line-through')).toBe(true);
    const status = fixture.nativeElement.querySelector(
      '[data-testid="agent-status"]',
    );
    expect(status?.textContent).toContain('retired');
  });

  it('should expose copy agent name button with CDK Clipboard binding', async () => {
    setupFixture();
    await loadAndSettle(baseAgent);

    const copyBtn = fixture.nativeElement.querySelector(
      '[data-testid="agent-copy-name"]',
    );
    expect(copyBtn).toBeTruthy();
    expect(copyBtn?.getAttribute('aria-label')).toBe(
      'Copy agent name to clipboard',
    );
  });

  it('should render error state when fetch fails', async () => {
    setupFixture();
    await loadAndSettle(null);

    const alert = (fixture.nativeElement as HTMLElement).querySelector(
      '[role="alert"]',
    );
    expect(alert?.textContent).toContain('Failed');
  });
});
// vi import is required for type discovery in some configs; not actually spying here
void vi;
