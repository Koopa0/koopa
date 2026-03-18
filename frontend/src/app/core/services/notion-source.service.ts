import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiNotionSource,
  ApiCreateNotionSourceRequest,
  ApiUpdateNotionSourceRequest,
  ApiDiscoveredDatabase,
} from '../models';

/** Admin CRUD for Notion source databases */
@Injectable({ providedIn: 'root' })
export class NotionSourceService {
  private readonly api = inject(ApiService);

  discover(): Observable<ApiDiscoveredDatabase[]> {
    return this.api.getData<ApiDiscoveredDatabase[]>('/api/admin/notion-sources/discover');
  }

  list(): Observable<ApiNotionSource[]> {
    return this.api.getData<ApiNotionSource[]>('/api/admin/notion-sources');
  }

  getById(id: string): Observable<ApiNotionSource> {
    return this.api.getData<ApiNotionSource>(`/api/admin/notion-sources/${id}`);
  }

  create(body: ApiCreateNotionSourceRequest): Observable<ApiNotionSource> {
    return this.api.postData<ApiNotionSource>('/api/admin/notion-sources', body);
  }

  update(id: string, body: ApiUpdateNotionSourceRequest): Observable<ApiNotionSource> {
    return this.api.putData<ApiNotionSource>(`/api/admin/notion-sources/${id}`, body);
  }

  delete(id: string): Observable<void> {
    return this.api.delete(`/api/admin/notion-sources/${id}`);
  }

  toggle(id: string): Observable<ApiNotionSource> {
    return this.api.postData<ApiNotionSource>(`/api/admin/notion-sources/${id}/toggle`, {});
  }
}
