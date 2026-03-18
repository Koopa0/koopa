import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiSpacedDueResponse,
  ApiSpacedInterval,
  ApiSubmitReviewRequest,
  ApiEnrollRequest,
} from '../models';

/** Admin service for spaced repetition */
@Injectable({ providedIn: 'root' })
export class SpacedService {
  private readonly api = inject(ApiService);

  listDue(limit = 50): Observable<ApiSpacedDueResponse> {
    return this.api.getData<ApiSpacedDueResponse>('/api/admin/spaced/due', { limit });
  }

  submitReview(body: ApiSubmitReviewRequest): Observable<ApiSpacedInterval> {
    return this.api.postData<ApiSpacedInterval>('/api/admin/spaced/review', body);
  }

  enroll(body: ApiEnrollRequest): Observable<ApiSpacedInterval> {
    return this.api.postData<ApiSpacedInterval>('/api/admin/spaced/enroll', body);
  }
}
