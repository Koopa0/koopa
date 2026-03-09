import { Injectable, signal, computed } from '@angular/core';
import { Observable } from 'rxjs';
import {
  Project,
  CreateProjectRequest,
  UpdateProjectRequest,
} from '../../models/project.model';
import { MOCK_PROJECTS } from '../mock-projects';

@Injectable({ providedIn: 'root' })
export class ProjectService {
  private readonly projects = signal<Project[]>(MOCK_PROJECTS);

  readonly allProjects = this.projects.asReadonly();

  readonly featuredProjects = computed(() =>
    this.projects()
      .filter((p) => p.featured)
      .sort((a, b) => a.order - b.order),
  );

  getProjectBySlug(slug: string): Project | undefined {
    return this.projects().find((p) => p.slug === slug);
  }

  getProjectById(id: string): Project | undefined {
    return this.projects().find((p) => p.id === id);
  }

  createProject(request: CreateProjectRequest): Observable<Project> {
    return new Observable((observer) => {
      setTimeout(() => {
        const newProject: Project = {
          ...request,
          id: `proj-${Date.now()}`,
        };

        this.projects.update((list) => [...list, newProject]);
        observer.next(newProject);
        observer.complete();
      }, 500);
    });
  }

  updateProject(request: UpdateProjectRequest): Observable<Project> {
    return new Observable((observer) => {
      setTimeout(() => {
        const index = this.projects().findIndex((p) => p.id === request.id);
        if (index === -1) {
          observer.error(new Error('Project not found'));
          return;
        }

        const current = this.projects()[index];
        const updated: Project = { ...current, ...request };

        this.projects.update((list) =>
          list.map((p) => (p.id === request.id ? updated : p)),
        );

        observer.next(updated);
        observer.complete();
      }, 500);
    });
  }

  deleteProject(id: string): Observable<void> {
    return new Observable((observer) => {
      setTimeout(() => {
        const exists = this.projects().some((p) => p.id === id);
        if (!exists) {
          observer.error(new Error('Project not found'));
          return;
        }

        this.projects.update((list) => list.filter((p) => p.id !== id));
        observer.next();
        observer.complete();
      }, 500);
    });
  }

  private generateSlug(title: string): string {
    return title
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .trim();
  }
}
