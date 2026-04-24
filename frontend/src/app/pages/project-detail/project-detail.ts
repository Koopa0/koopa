import {
  Component,
  DestroyRef,
  inject,
  signal,
  input,
  ChangeDetectionStrategy,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Location } from '@angular/common';
import {
  LucideAngularModule,
  ArrowLeft,
  Github,
  ExternalLink,
  CheckCircle2,
  Wrench,
  Code2,
} from 'lucide-angular';
import { ProjectService } from '../../core/services/project/project.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';
import type { ApiProject, ProjectStatus } from '../../core/models';

@Component({
  selector: 'app-project-detail',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './project-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectDetailComponent implements OnInit {
  /** Route param: projects/:slug */
  readonly slug = input.required<string>();

  private readonly location = inject(Location);
  private readonly projectService = inject(ProjectService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly project = signal<ApiProject | null>(null);
  protected readonly isLoading = signal(true);
  protected readonly isNotFound = signal(false);

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly GithubIcon = Github;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly CheckCircle2Icon = CheckCircle2;
  protected readonly WrenchIcon = Wrench;
  protected readonly Code2Icon = Code2;

  ngOnInit(): void {
    this.loadProject(this.slug());
  }

  private loadProject(slug: string): void {
    this.projectService.getProjectBySlug(slug).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (project) => {
        this.project.set(project);
        this.isLoading.set(false);
        this.updateSeo(project);
      },
      error: () => {
        this.isNotFound.set(true);
        this.isLoading.set(false);
      },
    });
  }

  private updateSeo(project: ApiProject): void {
    const projectUrl = `${environment.siteUrl}/projects/${project.slug}`;
    this.seoService.updateMeta({
      title: `${project.title} | Koopa`,
      description: project.description,
      ogTitle: project.title,
      ogDescription: project.description,
      ogUrl: projectUrl,
      ogType: 'website',
      canonicalUrl: projectUrl,
    });
  }

  protected goBack(): void {
    this.location.back();
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
}
