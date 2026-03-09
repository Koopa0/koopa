import { TestBed } from '@angular/core/testing';
import { BuildLogService } from './build-log.service';

describe('BuildLogService', () => {
  let service: BuildLogService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(BuildLogService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should return published build logs', () => {
    const published = service.publishedBuildLogs();
    expect(published.length).toBeGreaterThan(0);
    expect(published.every((bl) => bl.status === 'published')).toBeTrue();
  });

  it('should return latest build logs sorted by date desc', () => {
    const latest = service.latestBuildLogs();
    for (let i = 1; i < latest.length; i++) {
      expect(latest[i - 1].publishedAt.getTime()).toBeGreaterThanOrEqual(
        latest[i].publishedAt.getTime(),
      );
    }
  });

  it('should find build log by slug', (done) => {
    service.getBySlug('blog-ssr-implementation').subscribe({
      next: (bl) => {
        expect(bl.title).toContain('SSR');
        done();
      },
    });
  });

  it('should return error for non-existent slug', (done) => {
    service.getBySlug('non-existent').subscribe({
      error: (err) => {
        expect(err.message).toContain('not found');
        done();
      },
    });
  });

  it('should filter by project id', () => {
    const logs = service.getByProjectId('proj-001');
    expect(logs.length).toBeGreaterThan(0);
    expect(logs.every((bl) => bl.projectId === 'proj-001')).toBeTrue();
  });
});
