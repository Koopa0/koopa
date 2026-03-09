import { Injectable, inject, signal } from '@angular/core';
import { Observable, tap, catchError, throwError } from 'rxjs';
import { ApiService } from '../api.service';
import type {
  ApiProject,
  ApiCreateProjectRequest,
  ApiUpdateProjectRequest,
} from '../../models';

@Injectable({ providedIn: 'root' })
export class ProjectService {
  private readonly api = inject(ApiService);

  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly loading = this._loading.asReadonly();
  readonly errorMessage = this._error.asReadonly();

  /** Get all projects (public) */
  getAllProjects(): Observable<ApiProject[]> {
    this._loading.set(true);
    this._error.set(null);

    return this.api.getData<ApiProject[]>('/api/projects').pipe(
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('Failed to load projects');
        return throwError(() => err);
      }),
    );
  }

  /** Get single project by slug (public) */
  getProjectBySlug(slug: string): Observable<ApiProject> {
    this._loading.set(true);
    this._error.set(null);

    return this.api.getData<ApiProject>(`/api/projects/${slug}`).pipe(
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('Project not found');
        return throwError(() => err);
      }),
    );
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
