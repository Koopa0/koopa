import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  Github,
  ExternalLink,
  ArrowRight,
} from 'lucide-angular';
import { ProjectService } from '../../../core/services/project/project.service';
import { Project } from '../../../core/models';

@Component({
  selector: 'app-featured-projects',
  standalone: true,
  imports: [LucideAngularModule, RouterLink],
  template: `
    <section id="projects" class="border-b border-zinc-800 bg-zinc-950">
      <div class="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8">
        <div class="mb-12 text-center">
          <h2 class="text-3xl font-bold text-zinc-100">Featured Projects</h2>
          <p class="mt-3 text-zinc-400">
            精選的開源與個人專案，涵蓋後端服務、CLI 工具與全端應用
          </p>
        </div>

        <div class="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          @for (project of projects(); track project.id) {
            <div
              class="group flex flex-col rounded-sm border border-zinc-800 bg-zinc-900/50 p-6 transition-all duration-200 hover:-translate-y-1 hover:border-zinc-600 hover:shadow-lg hover:shadow-zinc-950/50"
            >
              <!-- Header -->
              <div class="mb-4">
                <a
                  [routerLink]="['/projects', project.slug]"
                  class="text-lg font-semibold text-zinc-100 no-underline hover:text-white"
                >
                  {{ project.title }}
                </a>
              </div>

              <!-- Description -->
              <p class="mb-4 flex-1 text-sm leading-relaxed text-zinc-400">
                {{ project.description }}
              </p>

              <!-- Tech Stack -->
              <div class="mb-4 flex flex-wrap gap-1.5">
                @for (tech of project.techStack; track tech) {
                  <span
                    class="rounded-sm bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400"
                  >
                    {{ tech }}
                  </span>
                }
              </div>

              <!-- Links -->
              <div
                class="flex items-center gap-3 border-t border-zinc-800 pt-4"
              >
                @if (project.githubUrl) {
                  <a
                    [href]="project.githubUrl"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex items-center gap-1.5 text-xs text-zinc-500 no-underline transition-colors hover:text-zinc-200"
                  >
                    <lucide-icon [img]="GithubIcon" [size]="14" />
                    Source
                  </a>
                }
                @if (project.liveUrl) {
                  <a
                    [href]="project.liveUrl"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-flex items-center gap-1.5 text-xs text-zinc-500 no-underline transition-colors hover:text-zinc-200"
                  >
                    <lucide-icon [img]="ExternalLinkIcon" [size]="14" />
                    Live Demo
                  </a>
                }
                <a
                  [routerLink]="['/projects', project.slug]"
                  class="ml-auto inline-flex items-center gap-1 text-xs text-zinc-500 no-underline transition-colors hover:text-zinc-200"
                >
                  Details
                  <lucide-icon [img]="ArrowRightIcon" [size]="14" />
                </a>
              </div>
            </div>
          }
        </div>

        <div class="mt-10 text-center">
          <a
            routerLink="/projects"
            class="inline-flex items-center gap-2 text-sm text-zinc-400 no-underline transition-colors hover:text-zinc-200"
          >
            View All Projects
            <lucide-icon [img]="ArrowRightIcon" [size]="16" />
          </a>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class FeaturedProjectsComponent {
  private readonly projectService = inject(ProjectService);

  protected readonly projects = this.projectService.featuredProjects;

  protected readonly GithubIcon = Github;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly ArrowRightIcon = ArrowRight;

  protected getStatusLabel(status: Project['status']): string {
    const labels: Record<Project['status'], string> = {
      completed: 'Completed',
      'in-progress': 'In Progress',
      maintained: 'Maintained',
    };
    return labels[status];
  }

  protected getStatusClass(status: Project['status']): string {
    const classes: Record<Project['status'], string> = {
      completed: 'bg-emerald-900/50 text-emerald-400',
      'in-progress': 'bg-amber-900/50 text-amber-400',
      maintained: 'bg-sky-900/50 text-sky-400',
    };
    return classes[status];
  }
}
