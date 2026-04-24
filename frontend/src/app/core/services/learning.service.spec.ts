import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { LearningService } from './learning.service';
import type { LearningSummary } from '../models/workbench.model';

const mockSummary: LearningSummary = {
  state: 'ok',
  streak_days: 7,
  due_reviews: 4,
  domains: [
    {
      domain: 'leetcode',
      concepts_total: 12,
      concepts_mastered: 6,
      concepts_weak: 0,
      concepts_developing: 6,
    },
  ],
};

describe('LearningService', () => {
  let service: LearningService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(LearningService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch learning summary', () => {
    service.summary().subscribe((res) => {
      expect(res.streak_days).toBe(7);
      expect(res.due_reviews).toBe(4);
      expect(res.domains[0].concepts_developing).toBe(6);
      expect(res.state).toBe('ok');
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/learning/summary'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockSummary });
  });

  it('should surface warn state with weak concept reason', () => {
    service.summary().subscribe((res) => {
      expect(res.state).toBe('warn');
      expect(res.reason).toBe('binary-search struggling');
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/learning/summary'),
    );
    req.flush({
      data: {
        ...mockSummary,
        state: 'warn',
        reason: 'binary-search struggling',
        domains: [
          {
            ...mockSummary.domains[0],
            concepts_weak: 1,
            concepts_developing: 5,
          },
        ],
      },
    });
  });
});
