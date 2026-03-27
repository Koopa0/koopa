import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { PipelineService } from './pipeline.service';

describe('PipelineService', () => {
  let service: PipelineService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(PipelineService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should trigger sync', () => {
    service.triggerSync().subscribe();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/sync'),
    );
    expect(req.request.method).toBe('POST');
    req.flush({ data: null });
  });

  it('should trigger collect', () => {
    service.triggerCollect().subscribe();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/collect'),
    );
    expect(req.request.method).toBe('POST');
    req.flush({ data: null });
  });

  it('should trigger generate', () => {
    service.triggerGenerate().subscribe();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/generate'),
    );
    expect(req.request.method).toBe('POST');
    req.flush({ data: null });
  });

  it('should trigger digest', () => {
    service.triggerDigest().subscribe();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/digest'),
    );
    expect(req.request.method).toBe('POST');
    req.flush({ data: null });
  });

  it('should set triggering state during action', () => {
    expect(service.triggering()).toBeNull();

    service.triggerSync().subscribe();
    expect(service.triggering()).toBe('sync');

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/sync'),
    );
    req.flush({ data: null });
    expect(service.triggering()).toBeNull();
  });

  it('should trigger notion-sync', () => {
    service.triggerNotionSync().subscribe();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/notion-sync'),
    );
    expect(req.request.method).toBe('POST');
    req.flush({ data: null });
  });

  it('should trigger reconcile', () => {
    service.triggerReconcile().subscribe();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/reconcile'),
    );
    expect(req.request.method).toBe('POST');
    req.flush({ data: null });
  });

  it('should trigger bookmark', () => {
    service.triggerBookmark().subscribe();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/bookmark'),
    );
    expect(req.request.method).toBe('POST');
    req.flush({ data: null });
  });

  it('should reset triggering on error', () => {
    service.triggerCollect().subscribe({
      error: () => {
        /* expected */
      },
    });
    expect(service.triggering()).toBe('collect');

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/pipeline/collect'),
    );
    req.flush('Error', { status: 500, statusText: 'Server Error' });
    expect(service.triggering()).toBeNull();
  });
});
