import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
} from '@angular/core';
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
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import type { ApiProject, ProjectStatus } from '../../core/models';

@Component({
  selector: 'app-projects',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './projects.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class ProjectsComponent implements OnInit {
  private readonly projectService = inject(ProjectService);
  private readonly seoService = inject(SeoService);

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

  protected readonly statusFilters: Array<{
    value: ProjectStatus | 'all';
    label: string;
  }> = [
    { value: 'all', label: 'All' },
    { value: 'completed', label: 'Completed' },
    { value: 'in-progress', label: 'In Progress' },
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
      description: '開源與個人專案列表，涵蓋後端服務、CLI 工具與全端應用',
      ogUrl: 'https://koopa0.dev/projects',
    });
    this.loadProjects();
  }

  protected onStatusChange(status: ProjectStatus | 'all'): void {
    this.selectedStatus.set(status);
  }

  protected getStatusLabel(status: ProjectStatus): string {
    const labels: Record<ProjectStatus, string> = {
      'completed': 'Completed',
      'in-progress': 'In Progress',
      'maintained': 'Maintained',
      'archived': 'Archived',
    };
    return labels[status];
  }

  protected getStatusClass(status: ProjectStatus): string {
    const classes: Record<ProjectStatus, string> = {
      'completed': 'bg-emerald-900/50 text-emerald-400',
      'in-progress': 'bg-amber-900/50 text-amber-400',
      'maintained': 'bg-sky-900/50 text-sky-400',
      'archived': 'bg-zinc-800 text-zinc-400',
    };
    return classes[status];
  }

  private loadProjects(): void {
    this.projectService.getAllProjects().subscribe({
      next: (projects) => {
        this.projects.set(projects);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('載入專案失敗');
        this.isLoading.set(false);
      },
    });
  }
}
