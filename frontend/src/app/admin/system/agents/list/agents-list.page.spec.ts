import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideRouter } from '@angular/router';

import { AgentsListPageComponent } from './agents-list.page';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { Agent } from '../../../../core/models/workbench.model';

// Wire-contract spec for the agents roster. Ground truth is
// internal/agent/handler.go::agentResponse: GET /api/admin/system/agents
// returns api.Response{Data: []agentResponse} — a bare array under `data`,
// each row carrying exactly six fields (name, display_name, platform,
// description, optional schedule {name,trigger,expr,backend,purpose},
// status). No capability / task-count columns: the MCP-v3 contraction
// retired the A2A surface. This spec mocks the real HTTP boundary so a
// future drift back to the retired shape fails here.

// `planner` is the scheduled agent in registry.go (morning-briefing);
// `koopa0-dev` carries no schedule. Both are real roster entries.
// Typed to Agent[] so the fixture is a COMPILE-TIME wire-contract guard:
// any drift from the six-field agentResponse shape fails to compile here.
const AGENTS_WIRE: { data: Agent[] } = {
  data: [
    {
      name: 'planner',
      display_name: 'Planner',
      platform: 'claude-cowork',
      description: 'Daily planner — morning briefing and candidate day plan',
      schedule: {
        name: 'morning-briefing',
        trigger: 'cron',
        expr: '0 8 * * *',
        backend: 'cowork_desktop',
        purpose: 'Daily briefing — todos, projects, goals, hypotheses',
      },
      status: 'active',
    },
    {
      name: 'koopa0-dev',
      display_name: 'koopa',
      platform: 'claude-code',
      description: 'koopa development project',
      status: 'active',
    },
  ],
};

describe('AgentsListPageComponent', () => {
  let fixture: ComponentFixture<AgentsListPageComponent>;
  let httpMock: HttpTestingController;
  let el: HTMLElement;

  async function setup(wire: { data: Agent[] }): Promise<void> {
    TestBed.configureTestingModule({
      imports: [AgentsListPageComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    fixture = TestBed.createComponent(AgentsListPageComponent);
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/system/agents'),
    );
    expect(req.request.method).toBe('GET');
    req.flush(wire);

    // rxResource resolves on a macrotask — settle before asserting DOM.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  }

  afterEach(() => {
    httpMock.verify();
    TestBed.resetTestingModule();
  });

  it('should render a row per agent from the bare data array', async () => {
    await setup(AGENTS_WIRE);

    const rows = el.querySelectorAll('[data-testid^="agents-list-row-"]');
    expect(rows.length).toBe(2);
    expect(
      el.querySelector('[data-testid="agents-list-row-planner"]'),
    ).toBeTruthy();
    expect(
      el.querySelector('[data-testid="agents-list-row-koopa0-dev"]'),
    ).toBeTruthy();
    expect(
      el.querySelector('[data-testid="agents-count"]')?.textContent,
    ).toContain('2');
  });

  it('should render name, display_name, platform, and status for each agent', async () => {
    await setup(AGENTS_WIRE);

    const plannerRow = el.querySelector(
      '[data-testid="agents-list-row-planner"]',
    );
    expect(plannerRow?.textContent).toContain('Planner'); // display_name
    expect(plannerRow?.textContent).toContain('planner'); // name
    expect(plannerRow?.textContent).toContain('claude-cowork'); // platform
    expect(plannerRow?.textContent).toContain('active'); // status
  });

  it('should surface the schedule summary for a scheduled agent', async () => {
    await setup(AGENTS_WIRE);

    const plannerRow = el.querySelector(
      '[data-testid="agents-list-row-planner"]',
    );
    // scheduleSummary() prefers schedule.purpose.
    expect(plannerRow?.textContent).toContain('Daily briefing');

    // koopa0-dev has no schedule → em dash placeholder, never a crash.
    const devRow = el.querySelector(
      '[data-testid="agents-list-row-koopa0-dev"]',
    );
    expect(devRow?.textContent).toContain('—');
  });

  it('should NOT render any retired capability or task column', async () => {
    await setup(AGENTS_WIRE);

    const headers = Array.from(el.querySelectorAll('thead th')).map((th) =>
      th.textContent?.trim().toLowerCase(),
    );
    expect(headers).toEqual(['name', 'platform', 'schedule', 'status']);
    // The retired A2A columns must be absent from the rendered table.
    const table = el.querySelector('[data-testid="agents-list-table"]');
    expect(table?.textContent?.toLowerCase()).not.toContain('as creator');
    expect(table?.textContent?.toLowerCase()).not.toContain('as assignee');
    expect(table?.textContent?.toLowerCase()).not.toContain('capabilit');
    expect(table?.textContent?.toLowerCase()).not.toContain('blocked');
  });

  it('should show the empty state when the roster is empty', async () => {
    await setup({ data: [] });

    expect(el.querySelector('[data-testid="agents-list-table"]')).toBeNull();
    expect(el.textContent).toContain('No agents match this filter');
  });
});
