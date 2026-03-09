import { Injectable, signal, computed, inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

export interface CommandAction {
  id: string;
  label: string;
  group: string;
  keywords?: string[];
  action: () => void;
}

@Injectable({ providedIn: 'root' })
export class CommandPaletteService {
  private readonly router = inject(Router);
  private readonly authService = inject(AuthService);

  private readonly _isOpen = signal(false);
  readonly isOpen = this._isOpen.asReadonly();

  readonly isAuthenticated = this.authService.isAuthenticated;

  /** All available actions based on auth state */
  readonly actions = computed<CommandAction[]>(() => {
    const pages: CommandAction[] = [
      { id: 'home', label: 'Home', group: 'Pages', keywords: ['index', 'main'], action: () => this.navigate('/home') },
      { id: 'articles', label: 'Articles', group: 'Pages', keywords: ['blog', 'post', 'writing'], action: () => this.navigate('/articles') },
      { id: 'build-logs', label: 'Build Log', group: 'Pages', keywords: ['dev', 'journal'], action: () => this.navigate('/build-logs') },
      { id: 'til', label: 'TIL', group: 'Pages', keywords: ['today', 'learned', 'learning'], action: () => this.navigate('/til') },
      { id: 'notes', label: 'Notes', group: 'Pages', keywords: ['memo', 'snippet'], action: () => this.navigate('/notes') },
      { id: 'projects', label: 'Projects', group: 'Pages', keywords: ['portfolio', 'work'], action: () => this.navigate('/projects') },
      { id: 'resume', label: 'Resume', group: 'Pages', keywords: ['cv', 'experience'], action: () => this.navigate('/resume') },
      { id: 'uses', label: 'Uses', group: 'Pages', keywords: ['tools', 'setup', 'stack'], action: () => this.navigate('/uses') },
      { id: 'about', label: 'About', group: 'Pages', keywords: ['me', 'info'], action: () => this.navigate('/about') },
    ];

    if (this.isAuthenticated()) {
      const admin: CommandAction[] = [
        { id: 'admin-dashboard', label: 'Dashboard', group: 'Admin', keywords: ['admin', 'manage'], action: () => this.navigate('/admin') },
        { id: 'admin-new-article', label: 'New Article', group: 'Admin', keywords: ['create', 'write'], action: () => this.navigate('/admin/editor') },
        { id: 'admin-new-project', label: 'New Project', group: 'Admin', keywords: ['create', 'add'], action: () => this.navigate('/admin/project-editor') },
      ];
      return [...pages, ...admin];
    }

    return pages;
  });

  open(): void {
    this._isOpen.set(true);
  }

  close(): void {
    this._isOpen.set(false);
  }

  toggle(): void {
    this._isOpen.update((v) => !v);
  }

  private navigate(path: string): void {
    this.router.navigate([path]);
  }
}
