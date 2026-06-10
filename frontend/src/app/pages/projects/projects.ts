import {
  Component,
  ChangeDetectionStrategy,
  computed,
  inject,
  OnInit,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { rxResource } from '@angular/core/rxjs-interop';
import { LucideAngularModule, ArrowRight, FolderOpen } from 'lucide-angular';
import { ProjectService } from '../../core/services/project/project.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiPortfolioProject } from '../../core/models';

/**
 * The projects index — one featured card (the portfolio entry the
 * backend flags `featured`) above compact rows for the rest. Data comes
 * from GET /api/portfolio, the rich public profile shape; GET
 * /api/projects only carries bare rows.
 */
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

  protected readonly portfolioResource = rxResource<
    ApiPortfolioProject[],
    void
  >({
    stream: () => this.projectService.getPortfolio(),
  });

  protected readonly projects = computed(() =>
    this.portfolioResource.hasValue() ? this.portfolioResource.value() : [],
  );

  /** The backend-flagged featured project (first one when several). */
  protected readonly featured = computed(
    () => this.projects().find((p) => p.featured) ?? null,
  );

  /** Everything that is not the featured card, as compact rows. */
  protected readonly rest = computed(() => {
    const featured = this.featured();
    return this.projects().filter((p) => p !== featured);
  });

  protected readonly isLoading = computed(
    () => this.portfolioResource.status() === 'loading',
  );

  protected readonly hasError = computed(
    () => this.portfolioResource.status() === 'error',
  );

  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly FolderOpenIcon = FolderOpen;

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
