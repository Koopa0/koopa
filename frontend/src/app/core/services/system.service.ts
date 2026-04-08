import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { SystemHealth } from '../models/admin.model';

/** 系統健康服務 — 基礎設施監控 API */
@Injectable({ providedIn: 'root' })
export class SystemService {
  private readonly api = inject(ApiService);

  /** 取得系統健康狀態：feeds、pipeline、AI 預算、資料庫 */
  getHealth(): Observable<SystemHealth> {
    return this.api.getData<SystemHealth>('/api/admin/system/health');
  }
}
