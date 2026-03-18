import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiTrackingTopic,
  ApiCreateTrackingTopicRequest,
  ApiUpdateTrackingTopicRequest,
} from '../models';

/** Admin CRUD for tracking topics */
@Injectable({ providedIn: 'root' })
export class TrackingService {
  private readonly api = inject(ApiService);

  list(): Observable<ApiTrackingTopic[]> {
    return this.api.getData<ApiTrackingTopic[]>('/api/admin/tracking');
  }

  create(body: ApiCreateTrackingTopicRequest): Observable<ApiTrackingTopic> {
    return this.api.postData<ApiTrackingTopic>('/api/admin/tracking', body);
  }

  update(id: string, body: ApiUpdateTrackingTopicRequest): Observable<ApiTrackingTopic> {
    return this.api.putData<ApiTrackingTopic>(`/api/admin/tracking/${id}`, body);
  }

  delete(id: string): Observable<void> {
    return this.api.delete(`/api/admin/tracking/${id}`);
  }
}
