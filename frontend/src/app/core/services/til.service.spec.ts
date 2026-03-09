import { TestBed } from '@angular/core/testing';
import { TilService } from './til.service';

describe('TilService', () => {
  let service: TilService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(TilService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should return published TILs sorted by date desc', () => {
    const tils = service.publishedTils();
    expect(tils.length).toBeGreaterThan(0);
    for (let i = 1; i < tils.length; i++) {
      expect(tils[i - 1].publishedAt.getTime()).toBeGreaterThanOrEqual(
        tils[i].publishedAt.getTime(),
      );
    }
  });

  it('should find TIL by slug', (done) => {
    service.getBySlug('go-context-timeout').subscribe({
      next: (til) => {
        expect(til.title).toContain('context');
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

  it('should filter by tag', () => {
    const goTils = service.getByTag('Golang');
    expect(goTils.length).toBeGreaterThan(0);
    expect(goTils.every((t) => t.tags.includes('Golang'))).toBeTrue();
  });
});
