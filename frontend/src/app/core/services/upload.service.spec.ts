import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { UploadService } from './upload.service';

describe('UploadService', () => {
  let service: UploadService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(UploadService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('validate', () => {
    it('should return null for valid JPEG file', () => {
      const file = new File(['data'], 'test.jpg', { type: 'image/jpeg' });
      expect(service.validate(file)).toBeNull();
    });

    it('should return null for valid PNG file', () => {
      const file = new File(['data'], 'test.png', { type: 'image/png' });
      expect(service.validate(file)).toBeNull();
    });

    it('should return null for valid WebP file', () => {
      const file = new File(['data'], 'test.webp', { type: 'image/webp' });
      expect(service.validate(file)).toBeNull();
    });

    it('should return null for valid GIF file', () => {
      const file = new File(['data'], 'test.gif', { type: 'image/gif' });
      expect(service.validate(file)).toBeNull();
    });

    it('should return error message for unsupported file type', () => {
      const file = new File(['data'], 'test.bmp', { type: 'image/bmp' });
      const result = service.validate(file);
      expect(result).toBeTruthy();
      expect(result).toContain('不支援的檔案格式');
    });

    it('should return error message for PDF file', () => {
      const file = new File(['data'], 'doc.pdf', { type: 'application/pdf' });
      const result = service.validate(file);
      expect(result).toContain('不支援的檔案格式');
    });

    it('should return error message when file exceeds 5MB', () => {
      const largeContent = new Uint8Array(5 * 1024 * 1024 + 1);
      const file = new File([largeContent], 'large.png', { type: 'image/png' });
      const result = service.validate(file);
      expect(result).toBeTruthy();
      expect(result).toContain('5MB');
    });

    it('should return null for file exactly at 5MB limit', () => {
      const content = new Uint8Array(5 * 1024 * 1024);
      const file = new File([content], 'exact.png', { type: 'image/png' });
      expect(service.validate(file)).toBeNull();
    });
  });

  describe('upload', () => {
    it('should POST FormData to upload endpoint and return URL', () => {
      const file = new File(['image-data'], 'photo.png', { type: 'image/png' });

      service.upload(file).subscribe((result) => {
        expect(result.url).toBe('https://r2.example.com/photo.png');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/admin/upload'));
      expect(req.request.method).toBe('POST');
      expect(req.request.body instanceof FormData).toBe(true);
      req.flush({ data: { url: 'https://r2.example.com/photo.png' } });
    });

    it('should propagate upload errors', () => {
      const file = new File(['data'], 'test.png', { type: 'image/png' });

      service.upload(file).subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(413);
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/admin/upload'));
      req.flush('Payload Too Large', { status: 413, statusText: 'Payload Too Large' });
    });
  });
});
