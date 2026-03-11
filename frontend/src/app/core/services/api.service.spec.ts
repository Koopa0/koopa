import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { ApiService } from './api.service';
import type { ApiResponse, ApiListResponse, ApiPaginationMeta } from '../models';

interface TestItem {
  id: string;
  name: string;
}

function createMockMeta(overrides: Partial<ApiPaginationMeta> = {}): ApiPaginationMeta {
  return {
    total: 10,
    page: 1,
    per_page: 10,
    total_pages: 1,
    ...overrides,
  };
}

describe('ApiService', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('get', () => {
    it('should make GET request to correct URL', () => {
      service.get<TestItem>('/api/items').subscribe((res) => {
        expect(res.data.id).toBe('1');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items'));
      expect(req.request.method).toBe('GET');
      req.flush({ data: { id: '1', name: 'Test' } } as ApiResponse<TestItem>);
    });

    it('should include query params when provided', () => {
      service.get<TestItem>('/api/items', { page: 2, type: 'article' }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/items') &&
        r.params.get('page') === '2' &&
        r.params.get('type') === 'article',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: { id: '1', name: 'Test' } });
    });

    it('should skip null and undefined params', () => {
      service.get<TestItem>('/api/items', { page: 1, type: undefined as unknown as string }).subscribe();

      const req = httpMock.expectOne((r) => r.url.includes('/api/items'));
      expect(req.request.params.get('page')).toBe('1');
      expect(req.request.params.has('type')).toBe(false);
      req.flush({ data: { id: '1', name: 'Test' } });
    });
  });

  describe('getList', () => {
    it('should make GET request and return list response', () => {
      const mockMeta = createMockMeta();

      service.getList<TestItem>('/api/items').subscribe((res) => {
        expect(res.data).toHaveLength(1);
        expect(res.meta).toEqual(mockMeta);
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items'));
      expect(req.request.method).toBe('GET');
      req.flush({
        data: [{ id: '1', name: 'Test' }],
        meta: mockMeta,
      } as ApiListResponse<TestItem>);
    });
  });

  describe('getData', () => {
    it('should unwrap data from ApiResponse', () => {
      service.getData<TestItem>('/api/items/1').subscribe((item) => {
        expect(item.id).toBe('1');
        expect(item.name).toBe('Test');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items/1'));
      req.flush({ data: { id: '1', name: 'Test' } } as ApiResponse<TestItem>);
    });
  });

  describe('getListData', () => {
    it('should return full list response with meta', () => {
      const mockMeta = createMockMeta();

      service.getListData<TestItem>('/api/items').subscribe((res) => {
        expect(res.data).toHaveLength(2);
        expect(res.meta.total).toBe(10);
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items'));
      req.flush({
        data: [{ id: '1', name: 'A' }, { id: '2', name: 'B' }],
        meta: mockMeta,
      });
    });
  });

  describe('post', () => {
    it('should make POST request with body', () => {
      const body = { name: 'New Item' };

      service.post<TestItem>('/api/items', body).subscribe((res) => {
        expect(res.data.id).toBe('2');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items'));
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual(body);
      req.flush({ data: { id: '2', name: 'New Item' } });
    });
  });

  describe('postData', () => {
    it('should POST and unwrap response data', () => {
      service.postData<TestItem>('/api/items', { name: 'New' }).subscribe((item) => {
        expect(item.id).toBe('3');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items'));
      expect(req.request.method).toBe('POST');
      req.flush({ data: { id: '3', name: 'New' } });
    });
  });

  describe('put', () => {
    it('should make PUT request with body', () => {
      const body = { name: 'Updated' };

      service.put<TestItem>('/api/items/1', body).subscribe((res) => {
        expect(res.data.name).toBe('Updated');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items/1'));
      expect(req.request.method).toBe('PUT');
      expect(req.request.body).toEqual(body);
      req.flush({ data: { id: '1', name: 'Updated' } });
    });
  });

  describe('putData', () => {
    it('should PUT and unwrap response data', () => {
      service.putData<TestItem>('/api/items/1', { name: 'Updated' }).subscribe((item) => {
        expect(item.name).toBe('Updated');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items/1'));
      expect(req.request.method).toBe('PUT');
      req.flush({ data: { id: '1', name: 'Updated' } });
    });
  });

  describe('delete', () => {
    it('should make DELETE request', () => {
      service.delete('/api/items/1').subscribe();

      const req = httpMock.expectOne((r) => r.url.includes('/api/items/1'));
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });

  describe('postVoid', () => {
    it('should POST and return void', () => {
      service.postVoid('/api/items/1/publish', {}).subscribe((result) => {
        expect(result).toBeUndefined();
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items/1/publish'));
      expect(req.request.method).toBe('POST');
      req.flush(null);
    });
  });

  describe('uploadData', () => {
    it('should POST FormData and unwrap response', () => {
      const formData = new FormData();
      formData.append('file', new Blob(['test']), 'test.png');

      service.uploadData<{ url: string }>('/api/admin/upload', formData).subscribe((result) => {
        expect(result.url).toBe('https://r2.example.com/test.png');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/admin/upload'));
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toBe(formData);
      req.flush({ data: { url: 'https://r2.example.com/test.png' } });
    });
  });

  describe('error propagation', () => {
    it('should propagate HTTP errors to subscriber', () => {
      service.getData<TestItem>('/api/items/999').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(404);
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items/999'));
      req.flush('Not Found', { status: 404, statusText: 'Not Found' });
    });

    it('should propagate server errors to subscriber', () => {
      service.postData<TestItem>('/api/items', {}).subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(500);
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/items'));
      req.flush('Server Error', { status: 500, statusText: 'Internal Server Error' });
    });
  });
});
