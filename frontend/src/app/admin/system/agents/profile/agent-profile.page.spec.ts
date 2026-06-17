import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { of, throwError, type Observable } from 'rxjs';

import { AgentProfilePageComponent } from './agent-profile.page';
import { AgentService } from '../../../../core/services/agent.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { Agent } from '../../../../core/models/workbench.model';

// The Agent Profile is a read-only registry view over the six-field
// projection (name / display_name / platform / description / status, plus
// an optional schedule), sourced from GET /api/admin/system/agents/:name.
// Capability, task, and activity concepts were retired with the MCP-v3
// A2A coordination surface.

function plannerAgent(): Agent {
  return {
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
  };
}

describe('AgentProfilePageComponent', () => {
  let fixture: ComponentFixture<AgentProfilePageComponent>;

  afterEach(() => TestBed.resetTestingModule());

  async function render(get: () => Observable<Agent>): Promise<HTMLElement> {
    TestBed.configureTestingModule({
      imports: [AgentProfilePageComponent],
      providers: [
        provideRouter([]),
        {
          provide: AgentService,
          useValue: { get },
        },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    fixture = TestBed.createComponent(AgentProfilePageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('should render the hero with the six-field projection when the agent loads', async () => {
    const el = await render(() => of(plannerAgent()));

    const hero = el.querySelector('[data-testid="agent-hero"]');
    expect(hero).toBeTruthy();
    expect(hero?.textContent).toContain('Planner');
    expect(hero?.textContent).toContain('planner');
    expect(hero?.textContent).toContain('claude-cowork');
    expect(hero?.textContent).toContain('active');
  });

  it('should render the schedule detail when the agent carries one', async () => {
    const el = await render(() => of(plannerAgent()));

    const schedule = el.querySelector('[data-testid="agent-schedule"]');
    expect(schedule).toBeTruthy();
    expect(
      el.querySelector('[data-testid="agent-schedule-name"]')?.textContent,
    ).toContain('morning-briefing');
    expect(
      el.querySelector('[data-testid="agent-schedule-expr"]')?.textContent,
    ).toContain('0 8 * * *');
    expect(
      el.querySelector('[data-testid="agent-schedule-purpose"]')?.textContent,
    ).toContain('Daily briefing');
  });

  it('should omit the schedule section for an agent without a schedule', async () => {
    const el = await render(() =>
      of({
        name: 'koopa0-dev',
        display_name: 'koopa',
        platform: 'claude-code',
        description: 'koopa development project',
        status: 'active',
      } satisfies Agent),
    );

    expect(el.querySelector('[data-testid="agent-schedule"]')).toBeNull();
  });

  it('should not render any retired capability or task UI', async () => {
    const el = await render(() => of(plannerAgent()));

    expect(el.querySelector('[data-testid="agent-capabilities"]')).toBeNull();
    expect(el.querySelector('[data-testid="agent-tabs"]')).toBeNull();
    expect(el.querySelector('[data-testid="agent-workload"]')).toBeNull();
    expect(el.textContent).not.toContain('submit_tasks');
  });

  it('should show the error state when the agent fails to load', async () => {
    const el = await render(() =>
      throwError(() => new HttpErrorResponse({ status: 500 })),
    );

    expect(el.querySelector('[data-testid="agent-error"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="agent-profile"]')).toBeNull();
  });
});
