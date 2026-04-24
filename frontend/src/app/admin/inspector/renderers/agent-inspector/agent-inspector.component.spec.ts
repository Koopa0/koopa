import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';
import { AgentInspectorComponent } from './agent-inspector.component';
import type { AgentDetail } from '../../../../core/models/workbench.model';

const baseAgent: AgentDetail = {
  name: 'hq',
  display_name: 'Studio HQ',
  platform: 'claude-cowork',
  description: 'CEO — decisions, delegation, morning briefing',
  capability: {
    submit_tasks: true,
    receive_tasks: false,
    publish_artifacts: true,
  },
  schedule: {
    name: 'morning-briefing',
    trigger: 'cron',
    expr: '0 8 * * *',
    backend: 'cowork_desktop',
    purpose: 'Daily briefing — todos, projects, goals, RSS highlights',
  },
  status: 'active',
  open_task_count: 3,
  blocked_count: 0,
  activity_state: 'active',
  schedule_human_readable: 'Daily 8 AM briefing',
  last_task_accepted_at: '2026-04-17T03:00:00Z',
  retired_at: null,
};

describe('AgentInspectorComponent', () => {
  let fixture: ComponentFixture<AgentInspectorComponent>;
  let httpMock: HttpTestingController;

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
        provideRouter([]),
      ],
    });
    fixture = TestBed.createComponent(AgentInspectorComponent);
    httpMock = TestBed.inject(HttpTestingController);
  }

  function flushAll(name: string, response: AgentDetail | null): void {
    const reqs = httpMock.match((r) =>
      r.url.includes(`/api/admin/coordination/agents/${name}`),
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

  async function loadAndSettle(a: AgentDetail | null): Promise<void> {
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
    ).toContain('Studio HQ');
    const subtitle = el.querySelector('[data-testid="agent-subtitle"]');
    expect(subtitle?.textContent).toContain('hq');
    expect(subtitle?.textContent).toContain('claude-cowork');
  });

  it('should render capability inline as plain text (not dot-grid)', async () => {
    setupFixture();
    await loadAndSettle(baseAgent);

    const cap = fixture.nativeElement.querySelector(
      '[data-testid="agent-capabilities"]',
    );
    expect(cap?.textContent?.trim()).toBe(
      'submits tasks · publishes artifacts',
    );
    // Must NOT contain dot-grid SVG or matrix indicator
    expect(cap?.querySelector('svg')).toBeFalsy();
  });

  it('should omit capability row entirely for passive identity (all bits false)', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseAgent,
      name: 'koopa0-dev',
      capability: {
        submit_tasks: false,
        receive_tasks: false,
        publish_artifacts: false,
      },
    });

    const cap = fixture.nativeElement.querySelector(
      '[data-testid="agent-capabilities"]',
    );
    expect(cap).toBeFalsy();
  });

  it('should render schedule as human-readable, NOT cron literal in default view', async () => {
    setupFixture();
    await loadAndSettle(baseAgent);

    const sched = fixture.nativeElement.querySelector(
      '[data-testid="agent-schedule"]',
    );
    expect(sched?.textContent?.trim()).toBe('Daily 8 AM briefing');
    expect(sched?.textContent).not.toContain('0 8 * * *');
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

  it('should render system agent warning for system fallback identity', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseAgent,
      name: 'system',
      display_name: 'System',
      platform: 'human',
      description:
        'Database-level writes without Go caller context — pg_cron jobs',
      capability: {
        submit_tasks: false,
        receive_tasks: false,
        publish_artifacts: false,
      },
      schedule: undefined,
    });

    const warning = fixture.nativeElement.querySelector(
      '[data-testid="agent-system-warning"]',
    );
    expect(warning).toBeTruthy();
    expect(warning?.textContent).toContain('fallback identity');
  });

  it('should render retired status with line-through title + retired_at in subtitle', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseAgent,
      status: 'retired',
      retired_at: '2026-04-10T00:00:00Z',
    });

    const title = fixture.nativeElement.querySelector(
      '[data-testid="agent-display-name"]',
    );
    expect(title?.classList.contains('line-through')).toBe(true);
    const subtitle = fixture.nativeElement.querySelector(
      '[data-testid="agent-subtitle"]',
    );
    expect(subtitle?.textContent).toContain('retired');
  });

  it('should render tail link with N open tasks pointing to Atlas filtered', async () => {
    setupFixture();
    await loadAndSettle(baseAgent);

    const link = fixture.nativeElement.querySelector(
      '[data-testid="agent-open-tasks-link"]',
    );
    expect(link?.textContent).toContain('View 3 open tasks for hq');
    // routerLink resolves to /admin/atlas with queryParams assignee=hq
    expect(link?.getAttribute('aria-label')).toContain('open tasks for hq');
  });

  it('should render "No open tasks" when count is 0', async () => {
    setupFixture();
    await loadAndSettle({ ...baseAgent, open_task_count: 0 });

    const empty = fixture.nativeElement.querySelector(
      '[data-testid="agent-no-open-tasks"]',
    );
    expect(empty?.textContent).toContain('No open tasks');
    const link = fixture.nativeElement.querySelector(
      '[data-testid="agent-open-tasks-link"]',
    );
    expect(link).toBeFalsy();
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
