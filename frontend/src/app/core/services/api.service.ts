import { Injectable, inject, PLATFORM_ID } from '@angular/core';
import { isPlatformServer } from '@angular/common';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, map } from 'rxjs';
import { environment } from '../../../environments/environment';
import type { ApiResponse, ApiListResponse } from '../models';

/** 根據執行環境（SSR / Browser）選擇正確的 API base URL */
@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly platformId = inject(PLATFORM_ID);

  private get baseUrl(): string {
    return isPlatformServer(this.platformId)
      ? environment.ssrApiUrl
      : environment.apiUrl;
  }

  /** 組合完整 URL：baseUrl + path（path 應以 / 開頭） */
  private url(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  get<T>(path: string, params?: Record<string, string | number>): Observable<ApiResponse<T>> {
    let httpParams = new HttpParams();
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          httpParams = httpParams.set(key, String(value));
        }
      }
    }
    return this.http.get<ApiResponse<T>>(this.url(path), { params: httpParams });
  }

  getList<T>(path: string, params?: Record<string, string | number>): Observable<ApiListResponse<T>> {
    let httpParams = new HttpParams();
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          httpParams = httpParams.set(key, String(value));
        }
      }
    }
    return this.http.get<ApiListResponse<T>>(this.url(path), { params: httpParams });
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

  /** 取得單筆資料，自動解包 { data: T } */
  getData<T>(path: string, params?: Record<string, string | number>): Observable<T> {
    return this.get<T>(path, params).pipe(map((res) => res.data));
  }

  /** 取得列表資料，回傳 { data, meta } */
  getListData<T>(path: string, params?: Record<string, string | number>): Observable<ApiListResponse<T>> {
    return this.getList<T>(path, params);
  }

  /** POST 並解包 { data: T } */
  postData<T>(path: string, body: unknown): Observable<T> {
    return this.post<T>(path, body).pipe(map((res) => res.data));
  }

  /** PUT 並解包 { data: T } */
  putData<T>(path: string, body: unknown): Observable<T> {
    return this.put<T>(path, body).pipe(map((res) => res.data));
  }
}
