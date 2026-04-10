import { Injectable, inject, PLATFORM_ID } from '@angular/core';
import { isPlatformServer } from '@angular/common';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, map } from 'rxjs';
import { environment } from '../../../environments/environment';
import type { ApiResponse, ApiListResponse } from '../models';

/** Selects the correct API base URL based on runtime environment (SSR / Browser) */
@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly platformId = inject(PLATFORM_ID);

  private get baseUrl(): string {
    return isPlatformServer(this.platformId)
      ? environment.ssrApiUrl
      : environment.apiUrl;
  }

  /** Build full URL: baseUrl + path (path should start with /) */
  private url(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  get<T>(
    path: string,
    params?: Record<string, string | number>,
  ): Observable<ApiResponse<T>> {
    return this.http.get<ApiResponse<T>>(this.url(path), {
      params: this.buildParams(params),
    });
  }

  getList<T>(
    path: string,
    params?: Record<string, string | number>,
  ): Observable<ApiListResponse<T>> {
    return this.http.get<ApiListResponse<T>>(this.url(path), {
      params: this.buildParams(params),
    });
  }

  private buildParams(params?: Record<string, string | number>): HttpParams {
    let httpParams = new HttpParams();
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          httpParams = httpParams.set(key, String(value));
        }
      }
    }
    return httpParams;
  }

  post<T>(path: string, body: unknown): Observable<ApiResponse<T>> {
    return this.http.post<ApiResponse<T>>(this.url(path), body);
  }

  put<T>(path: string, body: unknown): Observable<ApiResponse<T>> {
    return this.http.put<ApiResponse<T>>(this.url(path), body);
  }

  delete(path: string): Observable<void> {
    return this.http.delete<void>(this.url(path));
  }

  /**
   * Get single item. Auto-unwraps { data: T } when present, otherwise returns
   * the raw body. Public endpoints (content/handler.go) use api.Response{Data:}
   * wrapping; admin endpoints (internal/admin/*) encode structs directly. This
   * smart-unwrap lets one service method handle both contracts without
   * duplicating 16 admin services.
   */
  getData<T>(
    path: string,
    params?: Record<string, string | number>,
  ): Observable<T> {
    return this.http
      .get<
        T | ApiResponse<T>
      >(this.url(path), { params: this.buildParams(params) })
      .pipe(map((res) => this.unwrap<T>(res)));
  }

  private unwrap<T>(res: T | ApiResponse<T>): T {
    if (
      res !== null &&
      typeof res === 'object' &&
      'data' in (res as object) &&
      (res as ApiResponse<T>).data !== undefined
    ) {
      return (res as ApiResponse<T>).data;
    }
    return res as T;
  }

  /** Get list data, returns { data, meta } */
  getListData<T>(
    path: string,
    params?: Record<string, string | number>,
  ): Observable<ApiListResponse<T>> {
    return this.getList<T>(path, params);
  }

  /** POST and smart-unwrap { data: T } when present. */
  postData<T>(path: string, body: unknown): Observable<T> {
    return this.http
      .post<T | ApiResponse<T>>(this.url(path), body)
      .pipe(map((res) => this.unwrap<T>(res)));
  }

  patch<T>(path: string, body: unknown): Observable<ApiResponse<T>> {
    return this.http.patch<ApiResponse<T>>(this.url(path), body);
  }

  /** PATCH and smart-unwrap { data: T } when present. */
  patchData<T>(path: string, body: unknown): Observable<T> {
    return this.http
      .patch<T | ApiResponse<T>>(this.url(path), body)
      .pipe(map((res) => this.unwrap<T>(res)));
  }

  /** PUT and smart-unwrap { data: T } when present. */
  putData<T>(path: string, body: unknown): Observable<T> {
    return this.http
      .put<T | ApiResponse<T>>(this.url(path), body)
      .pipe(map((res) => this.unwrap<T>(res)));
  }

  /** POST for endpoints returning 204 with no body */
  postVoid(path: string, body: unknown): Observable<void> {
    return this.http.post(this.url(path), body).pipe(map(() => undefined));
  }

  /** POST multipart/form-data upload, smart-unwrap { data: T } when present. */
  uploadData<T>(path: string, formData: FormData): Observable<T> {
    return this.http
      .post<T | ApiResponse<T>>(this.url(path), formData)
      .pipe(map((res) => this.unwrap<T>(res)));
  }
}
