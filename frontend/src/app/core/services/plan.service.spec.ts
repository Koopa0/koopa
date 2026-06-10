import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';

import { PlanService } from './plan.service';
import type { GoalStatusUpdate } from './plan.service';
import type { Milestone } from '../models/admin.model';

describe('PlanService', () => {
  let service: PlanService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(PlanService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    TestBed.resetTestingModule();
  });

  it('should POST the goal create body without a status field', () => {
    let created: { id: string } | undefined;
    service
      .createGoal({ title: 'Ship koopa v1', description: '' })
      .subscribe((g) => (created = g));

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/commitment/goals'),
    );
    expect(req.request.method).toBe('POST');
    expect(req.request.body).not.toHaveProperty('status');
    req.flush({ data: { id: 'g1', title: 'Ship koopa v1', status: 'not_started' } });

    expect(created?.id).toBe('g1');
  });

  it('should PUT the status and unwrap the partial projection', () => {
    let result: GoalStatusUpdate | undefined;
    service.updateGoalStatus('g1', 'done').subscribe((r) => (result = r));

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/commitment/goals/g1/status'),
    );
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ status: 'done' });
    req.flush({
      data: {
        title: 'Ship koopa v1',
        status: 'done',
        area_id: null,
        updated_at: '2026-06-10T00:00:00Z',
      },
    });

    expect(result?.status).toBe('done');
  });

  it('should POST a new milestone title to the goal milestones endpoint', () => {
    let milestone: Milestone | undefined;
    service.createMilestone('g1', 'Cut the RC').subscribe((m) => (milestone = m));

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/commitment/goals/g1/milestones'),
    );
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ title: 'Cut the RC' });
    req.flush({ data: { id: 'm1', goal_id: 'g1', title: 'Cut the RC' } });

    expect(milestone?.id).toBe('m1');
  });

  it('should POST to the milestone toggle endpoint', () => {
    let milestone: Milestone | undefined;
    service.toggleMilestone('g1', 'm1').subscribe((m) => (milestone = m));

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/commitment/goals/g1/milestones/m1/toggle'),
    );
    expect(req.request.method).toBe('POST');
    req.flush({
      data: { id: 'm1', goal_id: 'g1', completed_at: '2026-06-10T00:00:00Z' },
    });

    expect(milestone?.completed_at).toBe('2026-06-10T00:00:00Z');
  });
});
