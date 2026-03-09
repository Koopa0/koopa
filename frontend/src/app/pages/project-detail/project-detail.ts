import {
  Component,
  inject,
  signal,
  ChangeDetectionStrategy,
  OnInit,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
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
import { Project } from '../../core/models';

@Component({
  selector: 'app-project-detail',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './project-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly location = inject(Location);
  private readonly projectService = inject(ProjectService);
  private readonly seoService = inject(SeoService);

  protected readonly project = signal<Project | null>(null);
  protected readonly isNotFound = signal(false);

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly GithubIcon = Github;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly CheckCircle2Icon = CheckCircle2;
  protected readonly WrenchIcon = Wrench;
  protected readonly Code2Icon = Code2;

  ngOnInit(): void {
    const slug = this.route.snapshot.paramMap.get('slug');
    if (slug) {
      const project = this.projectService.getProjectBySlug(slug);
      if (project) {
        this.project.set(project);
        this.updateSeo(project);
      } else {
        this.isNotFound.set(true);
      }
    } else {
      this.isNotFound.set(true);
    }
  }

  private updateSeo(project: Project): void {
    const projectUrl = `https://koopa0.dev/projects/${project.slug}`;
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
