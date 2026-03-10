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

  /** 驗證檔案大小與類型，回傳錯誤訊息或 null */
  validate(file: File): string | null {
    if (!ACCEPTED_TYPES.includes(file.type)) {
      return '不支援的檔案格式，僅接受 JPEG、PNG、WebP、GIF';
    }
    if (file.size > MAX_FILE_SIZE) {
      return '檔案大小不得超過 5MB';
    }
    return null;
  }

  /** 上傳圖片至 R2，回傳 URL */
  upload(file: File): Observable<UploadResult> {
    const formData = new FormData();
    formData.append('file', file);
    return this.api.uploadData<UploadResult>('/api/admin/upload', formData);
  }
}
