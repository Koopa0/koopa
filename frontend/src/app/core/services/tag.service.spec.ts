import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TagService, type AdminTag } from './tag.service';

function makeTag(overrides: Partial<AdminTag> = {}): AdminTag {
  return {
    id: 'tag-1',
    slug: 'go',
    name: 'Go',
    description: '',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('TagService', () => {
  let service: TagService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(TagService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should list canonical tags when list is called', () => {
    let result: AdminTag[] | undefined;
    service.list().subscribe((tags) => (result = tags));

    const req = httpMock.expectOne(
      (r) => r.method === 'GET' && r.url.endsWith('/api/admin/knowledge/tags'),
    );
    req.flush({ data: [makeTag(), makeTag({ id: 'tag-2', slug: 'pg' })] });

    expect(result?.length).toBe(2);
    expect(result?.[0].slug).toBe('go');
  });

  it('should PUT the partial payload when update is called', () => {
    let result: AdminTag | undefined;
    service.update('tag-1', { name: 'Golang' }).subscribe((t) => (result = t));

    const req = httpMock.expectOne(
      (r) =>
        r.method === 'PUT' &&
        r.url.endsWith('/api/admin/knowledge/tags/tag-1'),
    );
    expect(req.request.body).toEqual({ name: 'Golang' });
    req.flush({ data: makeTag({ name: 'Golang' }) });

    expect(result?.name).toBe('Golang');
  });

  it('should POST source and target ids when merge is called', () => {
    let result: { aliases_moved: number } | undefined;
    service.merge('tag-1', 'tag-2').subscribe((r) => (result = r));

    const req = httpMock.expectOne(
      (r) =>
        r.method === 'POST' &&
        r.url.endsWith('/api/admin/knowledge/tags/merge'),
    );
    expect(req.request.body).toEqual({
      source_id: 'tag-1',
      target_id: 'tag-2',
    });
    req.flush({ data: { aliases_moved: 3, content_tags_moved: 7 } });

    expect(result?.aliases_moved).toBe(3);
  });
});
