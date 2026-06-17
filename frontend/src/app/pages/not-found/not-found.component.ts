import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, Home, FileText, User } from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';

@Component({
  selector: 'app-not-found',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    <section
      class="scanlines relative flex min-h-[calc(100vh-4rem)] items-center justify-center bg-bg px-4"
    >
      <div class="text-center">
        <p
          class="glitch-text font-display text-8xl font-bold text-fg-faint"
          data-text="404"
        >
          404
        </p>
        <h1 class="font-display mt-4 text-2xl font-bold text-fg">
          Page Not Found
        </h1>
        <p class="mt-2 text-sm text-fg-muted">
          The page you are looking for does not exist or has been removed.
        </p>
        <div class="mt-8 flex flex-wrap items-center justify-center gap-3">
          <a
            routerLink="/"
            class="inline-flex items-center gap-2 rounded-sm bg-white px-5 py-2.5 text-sm font-semibold text-bg no-underline transition-colors hover:bg-fg-muted"
          >
            <lucide-icon [img]="HomeIcon" [size]="16" />
            Back to Home
          </a>
          <a
            routerLink="/articles"
            class="inline-flex items-center gap-2 rounded-sm border border-border-strong px-5 py-2.5 text-sm text-fg-muted no-underline transition-colors hover:border-border-strong hover:text-white"
          >
            <lucide-icon [img]="FileTextIcon" [size]="16" />
            Articles
          </a>
          <a
            routerLink="/about"
            class="inline-flex items-center gap-2 rounded-sm border border-border-strong px-5 py-2.5 text-sm text-fg-muted no-underline transition-colors hover:border-border-strong hover:text-white"
          >
            <lucide-icon [img]="UserIcon" [size]="16" />
            About
          </a>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NotFoundComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: '404 - Page Not Found',
      description:
        'The page you are looking for does not exist or has been removed.',
      noIndex: true,
    });
  }

  protected readonly HomeIcon = Home;
  protected readonly FileTextIcon = FileText;
  protected readonly UserIcon = User;
}
