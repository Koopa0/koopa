import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '../api.service';
import type { ApiProject } from '../../models';

/**
 * Admin-only project projection. Project create / update / delete are
 * admin-only — Koopa runs them in the admin UI; there is no agent-facing
 * MCP path and no public portfolio surface.
 */
@Injectable({ providedIn: 'root' })
export class ProjectService {
  private readonly api = inject(ApiService);

  /** Admin — get all projects (including non-public) */
  getAdminProjects(): Observable<ApiProject[]> {
    return this.api.getData<ApiProject[]>('/api/admin/commitment/projects');
  }
}
