import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ACCEPTED_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

interface UploadResult {
  url: string;
}

@Injectable({ providedIn: 'root' })
export class UploadService {
  private readonly api = inject(ApiService);

  /** Validate file size and type, return error message or null */
  validate(file: File): string | null {
    if (!ACCEPTED_TYPES.includes(file.type)) {
      return 'Unsupported file format. Only JPEG, PNG, WebP, and GIF are accepted';
    }
    if (file.size > MAX_FILE_SIZE) {
      return 'File size must not exceed 5MB';
    }
    return null;
  }

  /** Upload image to R2, return URL */
  upload(file: File): Observable<UploadResult> {
    const formData = new FormData();
    formData.append('file', file);
    return this.api.uploadData<UploadResult>('/api/admin/upload', formData);
  }
}
