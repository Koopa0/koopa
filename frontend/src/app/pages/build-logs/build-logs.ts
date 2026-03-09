import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  OnInit,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Calendar,
  Clock,
  ArrowRight,
  Hammer,
} from 'lucide-angular';
import { BuildLogService } from '../../core/services/build-log.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import type { ApiContent } from '../../core/models';

@Component({
  selector: 'app-build-logs',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './build-logs.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class BuildLogsComponent implements OnInit {
  private readonly buildLogService = inject(BuildLogService);
  private readonly seoService = inject(SeoService);

  protected readonly buildLogs = signal<ApiContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly CalendarIcon = Calendar;
  protected readonly ClockIcon = Clock;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly HammerIcon = Hammer;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Build Log',
      description: 'Development logs — process, decisions, and lessons learned.',
      ogUrl: 'https://koopa0.dev/build-logs',
    });
    this.loadBuildLogs();
  }

  private loadBuildLogs(): void {
    this.buildLogService.getBuildLogs(1, 20).subscribe({
      next: (response) => {
        this.buildLogs.set(response.buildLogs);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('Failed to load build logs');
        this.isLoading.set(false);
      },
    });
  }
}
