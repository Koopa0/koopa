import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { AgentService } from './agent.service';
import type { AgentsResponse, AgentSummary } from '../models/workbench.model';

const mockAgent: AgentSummary = {
  name: 'research-lab',
  display_name: 'Research Lab',
  platform: 'claude-cowork',
  description: 'Deep research, structured reports',
  capability: {
    submit_tasks: true,
    receive_tasks: true,
    publish_artifacts: true,
  },
  status: 'active',
  open_task_count: 1,
  blocked_count: 0,
  activity_state: 'active',
};

const mockResponse: AgentsResponse = {
  state: 'ok',
  agents: [mockAgent],
};

describe('AgentService', () => {
  let service: AgentService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
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

  it('should fetch agents list', () => {
    service.list().subscribe((res) => {
      expect(res.agents).toHaveLength(1);
      expect(res.agents[0].activity_state).toBe('active');
      expect(res.state).toBe('ok');
    });

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/coordination/agents'));
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockResponse });
  });

  it('should surface warn state when any agent is blocked', () => {
    service.list().subscribe((res) => {
      expect(res.state).toBe('warn');
      expect(res.reason).toBe('rl: blocked 6d');
      expect(res.agents[0].activity_state).toBe('blocked');
    });

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/coordination/agents'));
    req.flush({
      data: {
        state: 'warn',
        reason: 'rl: blocked 6d',
        agents: [
          {
            ...mockAgent,
            activity_state: 'blocked',
            blocked_count: 1,
          },
        ],
      },
    });
  });

  it('should fetch single agent by name', () => {
    service.get('research-lab').subscribe((res) => {
      expect(res.name).toBe('research-lab');
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/coordination/agents/research-lab'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockAgent });
  });
});
