import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
  input,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, Home, RefreshCw, AlertTriangle } from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';

@Component({
  selector: 'app-error',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    <section
      class="flex min-h-[calc(100vh-4rem)] items-center justify-center bg-zinc-950 px-4"
    >
      <div class="text-center">
        <div class="mx-auto mb-6 flex size-16 items-center justify-center rounded-full border border-zinc-800 bg-zinc-900">
          <lucide-icon [img]="AlertTriangleIcon" [size]="32" class="text-zinc-500" />
        </div>
        <h1 class="text-2xl font-bold text-zinc-100">Something went wrong</h1>
        <p class="mt-2 max-w-md text-sm text-zinc-400">
          Sorry, an unexpected error occurred. Please try again later or go back to the home page.
        </p>
        <div class="mt-8 flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            (click)="reload()"
            class="inline-flex items-center gap-2 rounded-sm bg-white px-5 py-2.5 text-sm font-semibold text-zinc-900 transition-colors hover:bg-zinc-200"
          >
            <lucide-icon [img]="RefreshCwIcon" [size]="16" />
            Reload
          </button>
          <a
            routerLink="/"
            class="inline-flex items-center gap-2 rounded-sm border border-zinc-700 px-5 py-2.5 text-sm text-zinc-300 no-underline transition-colors hover:border-zinc-500 hover:text-white"
          >
            <lucide-icon [img]="HomeIcon" [size]="16" />
            Back to Home
          </a>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ErrorComponent implements OnInit {
  private readonly seoService = inject(SeoService);
  private readonly platformId = inject(PLATFORM_ID);

  readonly statusCode = input(500);

  protected readonly HomeIcon = Home;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly AlertTriangleIcon = AlertTriangle;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Error',
      description: 'An unexpected error occurred',
      noIndex: true,
    });
  }

  protected reload(): void {
    if (isPlatformBrowser(this.platformId)) {
      window.location.reload();
    }
  }
}
