import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  computed,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  Github,
  ExternalLink,
  ArrowRight,
  FolderOpen,
} from 'lucide-angular';
import { ProjectService } from '../../core/services/project/project.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiProject, ProjectStatus } from '../../core/models';

@Component({
  selector: 'app-projects',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './projects.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectsComponent implements OnInit {
  private readonly projectService = inject(ProjectService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly projects = signal<ApiProject[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly selectedStatus = signal<ProjectStatus | 'all'>('all');

  protected readonly filteredProjects = computed(() => {
    const status = this.selectedStatus();
    const allProjects = this.projects();
    if (status === 'all') {
      return allProjects;
    }
    return allProjects.filter((p) => p.status === status);
  });

  protected readonly statusFilters: {
    value: ProjectStatus | 'all';
    label: string;
  }[] = [
    { value: 'all', label: 'All' },
    { value: 'completed', label: 'Completed' },
    { value: 'in_progress', label: 'In Progress' },
    { value: 'maintained', label: 'Maintained' },
    { value: 'archived', label: 'Archived' },
  ];

  protected readonly GithubIcon = Github;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly FolderOpenIcon = FolderOpen;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Projects',
      description: 'Open-source and personal projects — backend services, CLI tools, and full-stack apps.',
      ogUrl: `${environment.siteUrl}/projects`,
      jsonLd: buildCollectionPageSchema({
        name: 'Projects',
        description: 'Open-source and personal projects — backend services, CLI tools, and full-stack apps.',
        url: `${environment.siteUrl}/projects`,
      }),
    });
    this.loadProjects();
  }

  protected onStatusChange(status: ProjectStatus | 'all'): void {
    this.selectedStatus.set(status);
  }

  protected getStatusLabel(status: ProjectStatus): string {
    const labels: Record<ProjectStatus, string> = {
      'planned': 'Planned',
      'in_progress': 'In Progress',
      'on_hold': 'On Hold',
      'completed': 'Completed',
      'maintained': 'Maintained',
      'archived': 'Archived',
    };
    return labels[status];
  }

  protected getStatusClass(status: ProjectStatus): string {
    const classes: Record<ProjectStatus, string> = {
      'planned': 'bg-zinc-800 text-zinc-300',
      'in_progress': 'bg-amber-900/50 text-amber-400',
      'on_hold': 'bg-orange-900/50 text-orange-400',
      'completed': 'bg-emerald-900/50 text-emerald-400',
      'maintained': 'bg-sky-900/50 text-sky-400',
      'archived': 'bg-zinc-800 text-zinc-400',
    };
    return classes[status];
  }

  protected loadProjects(): void {
    this.projectService.getAllProjects().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (projects) => {
        this.projects.set(projects);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('Failed to load projects');
        this.isLoading.set(false);
      },
    });
  }
}
