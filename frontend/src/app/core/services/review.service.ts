import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiReviewItem, ApiResponse } from '../models';

@Injectable({ providedIn: 'root' })
export class ReviewService {
  private readonly api = inject(ApiService);

  getReviews(): Observable<ApiResponse<ApiReviewItem[]>> {
    return this.api.get<ApiReviewItem[]>('/api/admin/review');
  }

  approveReview(id: string): Observable<void> {
    return this.api.postVoid(`/api/admin/review/${id}/approve`, {});
  }

  rejectReview(id: string, notes?: string): Observable<void> {
    return this.api.postVoid(`/api/admin/review/${id}/reject`, { notes: notes ?? '' });
  }

  editReview(id: string, notes: string): Observable<void> {
    return this.api.putData<void>(`/api/admin/review/${id}/edit`, { notes });
  }
}
