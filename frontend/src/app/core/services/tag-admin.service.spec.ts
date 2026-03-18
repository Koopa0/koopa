import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { TagAdminService } from './tag-admin.service';
import type { ApiTag, ApiTagAlias } from '../models';

describe('TagAdminService', () => {
  let service: TagAdminService;
  let httpTesting: HttpTestingController;

  const MOCK_TAG: ApiTag = {
    id: 'tag-1',
    slug: 'golang',
    name: 'Go',
    parent_id: null,
    description: 'Go programming language',
    created_at: '2026-03-17T00:00:00Z',
    updated_at: '2026-03-17T00:00:00Z',
  };

  const MOCK_ALIAS: ApiTagAlias = {
    id: 'alias-1',
    raw_tag: 'Go lang',
    tag_id: 'tag-1',
    match_method: 'case_insensitive',
    confirmed: false,
    confirmed_at: null,
    created_at: '2026-03-17T00:00:00Z',
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(TagAdminService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  describe('getTags', () => {
    it('should fetch all canonical tags when called', () => {
      service.getTags().subscribe((tags) => {
        expect(tags).toEqual([MOCK_TAG]);
      });

      const req = httpTesting.expectOne('/bff/api/admin/tags');
      expect(req.request.method).toBe('GET');
      req.flush({ data: [MOCK_TAG] });
    });
  });

  describe('createTag', () => {
    it('should create a new tag when given valid data', () => {
      const body = { slug: 'golang', name: 'Go' };
      service.createTag(body).subscribe((tag) => {
        expect(tag.slug).toBe('golang');
      });

      const req = httpTesting.expectOne('/bff/api/admin/tags');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual(body);
      req.flush({ data: MOCK_TAG });
    });
  });

  describe('updateTag', () => {
    it('should update an existing tag when given partial data', () => {
      service.updateTag('tag-1', { name: 'Golang' }).subscribe((tag) => {
        expect(tag).toBeTruthy();
      });

      const req = httpTesting.expectOne('/bff/api/admin/tags/tag-1');
      expect(req.request.method).toBe('PUT');
      req.flush({ data: { ...MOCK_TAG, name: 'Golang' } });
    });
  });

  describe('deleteTag', () => {
    it('should delete a tag when given valid id', () => {
      service.deleteTag('tag-1').subscribe();

      const req = httpTesting.expectOne('/bff/api/admin/tags/tag-1');
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });

  describe('getAliases', () => {
    it('should fetch all aliases when called without filter', () => {
      service.getAliases().subscribe((aliases) => {
        expect(aliases).toEqual([MOCK_ALIAS]);
      });

      const req = httpTesting.expectOne('/bff/api/admin/aliases');
      expect(req.request.method).toBe('GET');
      req.flush({ data: [MOCK_ALIAS] });
    });

    it('should pass unmapped param when unmapped filter is true', () => {
      service.getAliases(true).subscribe();

      const req = httpTesting.expectOne(
        (r) => r.url === '/bff/api/admin/aliases' && r.params.get('unmapped') === 'true',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [] });
    });
  });

  describe('mapAlias', () => {
    it('should map an alias to a tag when given valid ids', () => {
      service.mapAlias('alias-1', 'tag-1').subscribe((alias) => {
        expect(alias.match_method).toBe('manual');
      });

      const req = httpTesting.expectOne('/bff/api/admin/aliases/alias-1/map');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ tag_id: 'tag-1' });
      req.flush({ data: { ...MOCK_ALIAS, match_method: 'manual', confirmed: true } });
    });
  });

  describe('confirmAlias', () => {
    it('should confirm an alias when called', () => {
      service.confirmAlias('alias-1').subscribe((alias) => {
        expect(alias.confirmed).toBe(true);
      });

      const req = httpTesting.expectOne('/bff/api/admin/aliases/alias-1/confirm');
      expect(req.request.method).toBe('POST');
      req.flush({ data: { ...MOCK_ALIAS, confirmed: true } });
    });
  });

  describe('rejectAlias', () => {
    it('should reject an alias when called', () => {
      service.rejectAlias('alias-1').subscribe((alias) => {
        expect(alias.match_method).toBe('rejected');
      });

      const req = httpTesting.expectOne('/bff/api/admin/aliases/alias-1/reject');
      expect(req.request.method).toBe('POST');
      req.flush({ data: { ...MOCK_ALIAS, tag_id: null, match_method: 'rejected' } });
    });
  });

  describe('deleteAlias', () => {
    it('should delete an alias when given valid id', () => {
      service.deleteAlias('alias-1').subscribe();

      const req = httpTesting.expectOne('/bff/api/admin/aliases/alias-1');
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });
});
