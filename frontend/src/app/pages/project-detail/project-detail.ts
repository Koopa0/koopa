import {
  Component,
  ChangeDetectionStrategy,
  computed,
  effect,
  inject,
  input,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { rxResource } from '@angular/core/rxjs-interop';
import { catchError, forkJoin, map, of } from 'rxjs';
import { LucideAngularModule, Github, ExternalLink } from 'lucide-angular';
import { ProjectService } from '../../core/services/project/project.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildBreadcrumbSchema } from '../../core/services/seo/json-ld.util';
import { environment } from '../../../environments/environment';
import type { ApiPortfolioProject, ApiProject } from '../../core/models';

/**
 * The fields the project page renders. GET /api/projects/{slug} returns
 * only the bare project row, so the rich profile (role, tech stack,
 * narrative sections, highlights, links) is composed from the matching
 * GET /api/portfolio listing; the bare row is the fallback when the
 * project has no portfolio profile.
 */
interface ProjectProfile {
  slug: string;
  title: string;
  description: string;
  long_description: string | null;
  role: string | null;
  tech_stack: string[];
  highlights: string[];
  problem: string | null;
  solution: string | null;
  architecture: string | null;
  results: string | null;
  github_url: string | null;
  live_url: string | null;
}

function fromListing(listing: ApiPortfolioProject): ProjectProfile {
  return {
    slug: listing.slug,
    title: listing.title,
    description: listing.description,
    long_description: listing.long_description ?? null,
    role: listing.role ?? null,
    tech_stack: listing.tech_stack,
    highlights: listing.highlights,
    problem: listing.problem ?? null,
    solution: listing.solution ?? null,
    architecture: listing.architecture ?? null,
    results: listing.results ?? null,
    github_url: listing.github_url ?? null,
    live_url: listing.live_url ?? null,
  };
}

function fromBareRow(row: ApiProject): ProjectProfile {
  return {
    slug: row.slug,
    title: row.title,
    description: row.description,
    long_description: null,
    role: null,
    tech_stack: [],
    highlights: [],
    problem: null,
    solution: null,
    architecture: null,
    results: null,
    github_url: null,
    live_url: null,
  };
}

@Component({
  selector: 'app-project-detail',
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './project-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectDetailComponent {
  /** Route param: projects/:slug */
  readonly slug = input.required<string>();

  private readonly projectService = inject(ProjectService);
  private readonly seoService = inject(SeoService);

  protected readonly projectResource = rxResource<
    ProjectProfile | null,
    string
  >({
    params: () => this.slug(),
    stream: ({ params }) =>
      forkJoin({
        listings: this.projectService
          .getPortfolio()
          .pipe(catchError(() => of([] as ApiPortfolioProject[]))),
        row: this.projectService
          .getProjectBySlug(params)
          .pipe(catchError(() => of(null))),
      }).pipe(
        map(({ listings, row }) => {
          const listing = listings.find((l) => l.slug === params);
          if (listing) return fromListing(listing);
          return row ? fromBareRow(row) : null;
        }),
      ),
  });

  protected readonly project = computed(() =>
    this.projectResource.hasValue() ? this.projectResource.value() : null,
  );

  protected readonly isLoading = computed(
    () => this.projectResource.status() === 'loading',
  );

  protected readonly isNotFound = computed(
    () => !this.isLoading() && this.project() === null,
  );

  protected readonly GithubIcon = Github;
  protected readonly ExternalLinkIcon = ExternalLink;

  constructor() {
    effect(() => {
      const project = this.project();
      if (project) {
        this.updateSeo(project);
      }
    });
  }

  private updateSeo(project: ProjectProfile): void {
    const projectUrl = `${environment.siteUrl}/projects/${project.slug}`;
    this.seoService.updateMeta({
      title: project.title,
      description: project.description,
      ogTitle: project.title,
      ogDescription: project.description,
      ogUrl: projectUrl,
      ogType: 'website',
      canonicalUrl: projectUrl,
      jsonLd: buildBreadcrumbSchema([
        { name: 'koopa.dev', url: environment.siteUrl },
        { name: 'projects', url: `${environment.siteUrl}/projects` },
        { name: project.title, url: projectUrl },
      ]),
    });
  }
}
