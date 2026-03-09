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

  /** 取得所有專案（公開） */
  getAllProjects(): Observable<ApiProject[]> {
    this._loading.set(true);
    this._error.set(null);

    return this.api.getData<ApiProject[]>('/api/projects').pipe(
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('載入專案失敗');
        return throwError(() => err);
      }),
    );
  }

  /** 依 slug 取得單一專案（公開） */
  getProjectBySlug(slug: string): Observable<ApiProject> {
    this._loading.set(true);
    this._error.set(null);

    return this.api.getData<ApiProject>(`/api/projects/${slug}`).pipe(
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('專案不存在');
        return throwError(() => err);
      }),
    );
  }

  /** Admin — 建立專案 */
  createProject(request: ApiCreateProjectRequest): Observable<ApiProject> {
    return this.api.postData<ApiProject>('/api/admin/projects', request);
  }

  /** Admin — 更新專案 */
  updateProject(
    id: string,
    request: ApiUpdateProjectRequest,
  ): Observable<ApiProject> {
    return this.api.putData<ApiProject>(`/api/admin/projects/${id}`, request);
  }

  /** Admin — 刪除專案 */
  deleteProject(id: string): Observable<void> {
    return this.api.delete(`/api/admin/projects/${id}`);
  }
}
