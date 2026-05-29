import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { of, throwError, type Observable } from 'rxjs';

import { AgentProfilePageComponent } from './agent-profile.page';
import {
  AgentService,
  type AgentNoteRow,
} from '../../../../core/services/agent.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  AgentDetail,
  AgentTasksResponse,
} from '../../../../core/models/workbench.model';

// Product-truth guard for the Agent Profile notes tab.
// `/api/admin/coordination/agents/:name/notes` is a live backend route,
// so the notes tab must never claim "the agent notes endpoint is not
// live yet". A successful (even empty) load shows the empty state; an
// unexpected 404 shows an honest "couldn't load" banner; a real failure
// shows the transient error state.

function agentDetail(): AgentDetail {
  return {
    name: 'hq',
    display_name: 'Studio HQ',
    platform: 'claude-cowork',
    description: 'CEO, decisions, delegation',
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

function emptyTasks(): AgentTasksResponse {
  return { as_assignee: [], as_creator: [], recent_artifacts: [] };
}

describe('AgentProfilePageComponent — notes availability copy', () => {
  let fixture: ComponentFixture<AgentProfilePageComponent>;

  afterEach(() => TestBed.resetTestingModule());

  async function renderNotesTab(
    notes: () => Observable<AgentNoteRow[]>,
  ): Promise<HTMLElement> {
    TestBed.configureTestingModule({
      imports: [AgentProfilePageComponent],
      providers: [
        provideRouter([]),
        {
          provide: AgentService,
          useValue: {
            get: () => of(agentDetail()),
            tasks: () => of(emptyTasks()),
            notes,
          },
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

    const el = fixture.nativeElement as HTMLElement;
    const tab = el.querySelector(
      '[data-testid="agent-tab-notes"]',
    ) as HTMLButtonElement | null;
    expect(tab).toBeTruthy();
    tab?.click();
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    return el;
  }

  it('shows the empty notes state without stale "not live" copy when notes load', async () => {
    const el = await renderNotesTab(() => of([]));

    expect(
      el.querySelector('[data-testid="agent-notes-unavailable"]'),
    ).toBeNull();
    expect(el.textContent).not.toContain('not live yet');
    expect(el.textContent).toContain('No notes recorded.');
  });

  it('shows an honest "couldn\'t load" message (not "not live yet") on a 404', async () => {
    const el = await renderNotesTab(() =>
      throwError(() => new HttpErrorResponse({ status: 404 })),
    );

    const banner = el.querySelector(
      '[data-testid="agent-notes-unavailable"]',
    );
    expect(banner).toBeTruthy();
    expect(banner?.textContent).toContain("Couldn't load notes");
    expect(banner?.textContent).not.toContain('not live yet');
  });

  it('shows the transient error state on a real backend failure', async () => {
    const el = await renderNotesTab(() =>
      throwError(() => new HttpErrorResponse({ status: 500 })),
    );

    expect(
      el.querySelector('[data-testid="agent-notes-error"]'),
    ).toBeTruthy();
  });
});
