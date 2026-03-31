import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Calendar,
  Clock,
  ArrowRight,
  Hammer,
} from 'lucide-angular';
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-build-logs',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './build-logs.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BuildLogsComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly buildLogs = signal<ApiContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly HammerIcon = Hammer;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Build Logs',
      description: 'Development logs — process, decisions, and lessons learned.',
      ogUrl: `${environment.siteUrl}/build-logs`,
      jsonLd: buildCollectionPageSchema({
        name: 'Build Logs',
        description: 'Development logs — process, decisions, and lessons learned.',
        url: `${environment.siteUrl}/build-logs`,
      }),
    });
    this.loadBuildLogs();
  }

  protected loadBuildLogs(): void {
    this.contentService.listByType('build-log', { page: 1, perPage: 20 }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (response) => {
        this.buildLogs.set(response.data);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('Failed to load build logs');
        this.isLoading.set(false);
      },
    });
  }
}
