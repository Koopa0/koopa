import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { of, throwError, type Observable } from 'rxjs';

import { AgentProfilePageComponent } from './agent-profile.page';
import { AgentService } from '../../../../core/services/agent.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { AgentDetail } from '../../../../core/models/workbench.model';

// The Agent Profile is a read-only registry view: it renders the hero
// (name / display_name / platform / status) and the capability badges,
// both sourced from GET /api/admin/system/agents/:name. The A2A
// task/notes tabs were retired with the backend coordination endpoints.

function agentDetail(): AgentDetail {
  return {
    name: 'planner',
    display_name: 'Planner',
    platform: 'claude-cowork',
    description: 'planning, decisions, daily driving',
    capability: {
      submit_tasks: true,
      receive_tasks: false,
      publish_artifacts: true,
    },
    status: 'active',
    open_task_count: 0,
    blocked_count: 0,
    activity_state: 'idle',
  };
}

describe('AgentProfilePageComponent', () => {
  let fixture: ComponentFixture<AgentProfilePageComponent>;

  afterEach(() => TestBed.resetTestingModule());

  async function render(
    get: () => Observable<AgentDetail>,
  ): Promise<HTMLElement> {
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

  it('should render the hero and capability badges when the agent loads', async () => {
    const el = await render(() => of(agentDetail()));

    const hero = el.querySelector('[data-testid="agent-hero"]');
    expect(hero).toBeTruthy();
    expect(hero?.textContent).toContain('Planner');
    expect(hero?.textContent).toContain('planner');
    expect(hero?.textContent).toContain('claude-cowork');

    const capabilities = el.querySelector(
      '[data-testid="agent-capabilities"]',
    );
    expect(capabilities).toBeTruthy();
    expect(capabilities?.textContent).toContain('submit_tasks');
    expect(capabilities?.textContent).toContain('receive_tasks');
    expect(capabilities?.textContent).toContain('publish_artifacts');
  });

  it('should not render the retired task or notes tabs', async () => {
    const el = await render(() => of(agentDetail()));

    expect(el.querySelector('[data-testid="agent-tabs"]')).toBeNull();
    expect(el.querySelector('[data-testid="agent-workload"]')).toBeNull();
    expect(el.querySelector('[data-testid="agent-notes"]')).toBeNull();
  });

  it('should show the error state when the agent fails to load', async () => {
    const el = await render(() =>
      throwError(() => new HttpErrorResponse({ status: 500 })),
    );

    expect(el.querySelector('[data-testid="agent-error"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="agent-profile"]')).toBeNull();
  });
});
