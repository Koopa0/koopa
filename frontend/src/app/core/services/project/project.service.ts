import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiService } from '../api.service';
import type { ApiPortfolioProject, ApiProject } from '../../models';

/**
 * Project read-only service. Mutation (create / update / delete) lives
 * in Claude Cowork via `propose_commitment(type=project)`.
 */
@Injectable({ providedIn: 'root' })
export class ProjectService {
  private readonly api = inject(ApiService);

  /** Get all projects (public — filtered by backend WHERE public = true) */
  getAllProjects(): Observable<ApiProject[]> {
    return this.api.getData<ApiProject[]>('/api/projects');
  }

  /** Admin — get all projects (including non-public) */
  getAdminProjects(): Observable<ApiProject[]> {
    return this.api.getData<ApiProject[]>('/api/admin/commitment/projects');
  }

  /** Get single project by slug (public) — bare project row only */
  getProjectBySlug(slug: string): Observable<ApiProject> {
    return this.api.getData<ApiProject>(`/api/projects/${slug}`);
  }

  /**
   * Get the public portfolio (rich project profiles, public).
   * Array fields are normalized so templates can rely on them.
   */
  getPortfolio(): Observable<ApiPortfolioProject[]> {
    return this.api.getData<ApiPortfolioProject[]>('/api/portfolio').pipe(
      map((listings) =>
        (listings ?? []).map((listing) => ({
          ...listing,
          tech_stack: listing.tech_stack ?? [],
          highlights: listing.highlights ?? [],
        })),
      ),
    );
  }
}
