import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { AgentService } from './agent.service';
import type { Agent } from '../models/workbench.model';

const planner: Agent = {
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

const koopaDev: Agent = {
  name: 'koopa0-dev',
  display_name: 'koopa',
  platform: 'claude-code',
  description: 'koopa development project',
  status: 'active',
};

describe('AgentService', () => {
  let service: AgentService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(AgentService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch the agents roster as a bare array', () => {
    service.list().subscribe((agents) => {
      expect(agents).toHaveLength(2);
      expect(agents[0].name).toBe('planner');
      expect(agents[0].schedule?.expr).toBe('0 8 * * *');
      expect(agents[1].name).toBe('koopa0-dev');
      expect(agents[1].schedule).toBeUndefined();
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/system/agents'),
    );
    expect(req.request.method).toBe('GET');
    // Backend List returns api.Response{Data: []agentResponse} — a bare
    // array under `data`, no envelope key, no per-agent task counts.
    req.flush({ data: [planner, koopaDev] });
  });

  it('should fetch a single agent by name', () => {
    service.get('planner').subscribe((agent) => {
      expect(agent.name).toBe('planner');
      expect(agent.platform).toBe('claude-cowork');
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/system/agents/planner'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: planner });
  });
});
