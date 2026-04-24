import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { ConceptService } from './concept.service';
import type { ConceptDetail } from '../models/workbench.model';

const mockConcept: ConceptDetail = {
  id: 'concept-1',
  slug: 'binary-search',
  name: 'Binary Search',
  domain: 'leetcode',
  kind: 'pattern',
  description: 'Search a sorted array by halving the range each step.',
  created_at: '2026-04-01T00:00:00Z',
  mastery_stage: 'developing',
  mastery_counts: {
    weakness: 1,
    improvement: 1,
    mastery: 0,
    total: 2,
  },
  recent_attempts: [],
  recent_observations: [],
  parent_concept: null,
  low_confidence_count: 0,
  low_confidence_observations: [],
  targets_exercising_count: 0,
};

describe('ConceptService', () => {
  let service: ConceptService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ConceptService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch a concept by id and surface mastery stage', () => {
    service.get('concept-1').subscribe((res) => {
      expect(res.slug).toBe('binary-search');
      expect(res.mastery_stage).toBe('developing');
      expect(res.mastery_counts.total).toBe(2);
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/learning/concepts/concept-1'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockConcept });
  });
});
