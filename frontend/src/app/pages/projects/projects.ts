import {
  Component,
  ChangeDetectionStrategy,
  computed,
  inject,
  OnInit,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { rxResource } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  ArrowUpRight,
  FolderOpen,
  Github,
} from 'lucide-angular';
import { ProjectService } from '../../core/services/project/project.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiPortfolioProject } from '../../core/models';

/**
 * The projects index — editorial rows, the backend-flagged featured entry
 * first (rendered large), the rest below in the same row form. Each row is
 * a mono Role/Stack rail against a serif name, description, and highlights.
 * Data comes from GET /api/portfolio, the rich public profile shape.
 */
@Component({
  selector: 'app-projects',
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './projects.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectsComponent implements OnInit {
  private readonly projectService = inject(ProjectService);
  private readonly seoService = inject(SeoService);

  protected readonly portfolioResource = rxResource<
    ApiPortfolioProject[],
    void
  >({
    stream: () => this.projectService.getPortfolio(),
  });

  /** Featured project first, then the rest in their backend sort order. */
  protected readonly projects = computed(() => {
    const all = this.portfolioResource.hasValue()
      ? this.portfolioResource.value()
      : [];
    return [...all].sort((a, b) => {
      if (a.featured !== b.featured) {
        return a.featured ? -1 : 1;
      }
      return a.sort_order - b.sort_order;
    });
  });

  protected readonly isLoading = computed(
    () => this.portfolioResource.status() === 'loading',
  );

  protected readonly hasError = computed(
    () => this.portfolioResource.status() === 'error',
  );

  protected readonly ArrowUpRightIcon = ArrowUpRight;
  protected readonly FolderOpenIcon = FolderOpen;
  protected readonly GithubIcon = Github;

  ngOnInit(): void {
    const description =
      'Open-source and personal projects — backend services, CLI tools, and full-stack apps.';
    this.seoService.updateMeta({
      title: 'Projects',
      description,
      ogUrl: `${environment.siteUrl}/projects`,
      canonicalUrl: `${environment.siteUrl}/projects`,
      jsonLd: buildCollectionPageSchema({
        name: 'Projects',
        description,
        url: `${environment.siteUrl}/projects`,
      }),
    });
  }

  protected retry(): void {
    this.portfolioResource.reload();
  }
}
