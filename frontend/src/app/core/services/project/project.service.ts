import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '../api.service';
import type {
  ApiProject,
  ApiCreateProjectRequest,
  ApiUpdateProjectRequest,
} from '../../models';

@Injectable({ providedIn: 'root' })
export class ProjectService {
  private readonly api = inject(ApiService);

  /** Get all projects (public — filtered by backend WHERE public = true) */
  getAllProjects(): Observable<ApiProject[]> {
    return this.api.getData<ApiProject[]>('/api/projects');
  }

  /** Admin — get all projects (including non-public) */
  getAdminProjects(): Observable<ApiProject[]> {
    return this.api.getData<ApiProject[]>('/api/admin/projects');
  }

  /** Get single project by slug (public) */
  getProjectBySlug(slug: string): Observable<ApiProject> {
    return this.api.getData<ApiProject>(`/api/projects/${slug}`);
  }

  /** Admin — create project */
  createProject(request: ApiCreateProjectRequest): Observable<ApiProject> {
    return this.api.postData<ApiProject>('/api/admin/projects', request);
  }

  /** Admin — update project */
  updateProject(
    id: string,
    request: ApiUpdateProjectRequest,
  ): Observable<ApiProject> {
    return this.api.putData<ApiProject>(`/api/admin/projects/${id}`, request);
  }

  /** Admin — delete project */
  deleteProject(id: string): Observable<void> {
    return this.api.delete(`/api/admin/projects/${id}`);
  }
}
