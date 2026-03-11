import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { FlowRunService } from './flow-run.service';
import type { ApiFlowRun, ApiListResponse } from '../models';

describe('FlowRunService', () => {
  let service: FlowRunService;
  let httpMock: HttpTestingController;

  const mockFlowRun: ApiFlowRun = {
    id: '123',
    flow_name: 'content-review',
    content_id: '456',
    input: { title: 'Test' },
    output: null,
    status: 'completed',
    error: null,
    attempt: 1,
    max_attempts: 3,
    started_at: '2026-03-11T10:00:00Z',
    ended_at: '2026-03-11T10:00:05Z',
    created_at: '2026-03-11T10:00:00Z',
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(FlowRunService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch flow runs with default params', () => {
    const mockResponse: ApiListResponse<ApiFlowRun> = {
      data: [mockFlowRun],
      meta: { total: 1, page: 1, per_page: 20, total_pages: 1 },
    };

    service.getFlowRuns().subscribe((response) => {
      expect(response.data).toHaveLength(1);
      expect(response.data[0].flow_name).toBe('content-review');
    });

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/flow-runs'));
    expect(req.request.method).toBe('GET');
    req.flush(mockResponse);
  });

  it('should pass status filter as query param', () => {
    const mockResponse: ApiListResponse<ApiFlowRun> = {
      data: [],
      meta: { total: 0, page: 1, per_page: 20, total_pages: 0 },
    };

    service.getFlowRuns({ status: 'failed', page: 2 }).subscribe();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/flow-runs') &&
      r.params.get('status') === 'failed' &&
      r.params.get('page') === '2',
    );
    req.flush(mockResponse);
  });

  it('should retry a flow run', () => {
    service.retryFlowRun('123').subscribe();

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/flow-runs/123/retry'));
    expect(req.request.method).toBe('POST');
    req.flush({ data: null });
  });

  it('should fetch single flow run by id', () => {
    service.getFlowRun('123').subscribe((run) => {
      expect(run.id).toBe('123');
      expect(run.flow_name).toBe('content-review');
    });

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/flow-runs/123'));
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockFlowRun });
  });
});
