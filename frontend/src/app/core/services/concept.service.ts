import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ConceptDetail } from '../models/workbench.model';

/**
 * Concept service — single-concept detail fetch for Concept Inspector.
 * Uses uuid id (not slug) because concept slugs scope per-domain.
 * Read-only — concepts mutate via Cowork learning lifecycle.
 */
@Injectable({ providedIn: 'root' })
export class ConceptService {
  private readonly api = inject(ApiService);

  get(id: string): Observable<ConceptDetail> {
    return this.api.getData<ConceptDetail>(
      `/api/admin/learning/concepts/${id}`,
    );
  }
}
