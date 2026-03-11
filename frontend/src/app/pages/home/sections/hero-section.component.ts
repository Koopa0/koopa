import {
  Component,
  ChangeDetectionStrategy,
  inject,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { LucideAngularModule, ArrowRight, Code2, Mail } from 'lucide-angular';

@Component({
  selector: 'app-hero-section',
  standalone: true,
  imports: [LucideAngularModule],
  template: `
    <section class="relative overflow-hidden border-b border-zinc-800">
      <div
        class="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-zinc-800/30 via-zinc-950 to-zinc-950"
      ></div>
      <div
        class="relative mx-auto max-w-7xl px-4 py-24 sm:px-6 sm:py-32 lg:px-8 lg:py-40"
      >
        <div class="max-w-3xl">
          <p
            class="mb-4 inline-flex items-center gap-2 rounded-full border border-zinc-700 px-3 py-1 text-xs font-medium text-zinc-400"
          >
            <lucide-icon [img]="Code2Icon" [size]="12" />
            Software Engineer
          </p>
          <h1
            class="text-4xl font-bold tracking-tight text-zinc-100 sm:text-5xl lg:text-6xl"
          >
            Building reliable, high-performance
            <span class="text-zinc-500">backends that scale</span>
          </h1>
          <p class="mt-6 max-w-2xl text-lg leading-relaxed text-zinc-400">
            Focused on backend architecture and full-stack development. Building
            high-performance services with Go and Rust, crafting modern frontends with Angular.
          </p>
          <div class="mt-10 flex flex-wrap items-center gap-4">
            <button
              type="button"
              (click)="scrollTo('projects')"
              class="inline-flex cursor-pointer items-center gap-2 rounded-sm bg-white px-6 py-3 text-sm font-semibold text-zinc-900 no-underline transition-all hover:scale-[1.02] hover:bg-zinc-200 active:scale-[0.98]"
            >
              View Projects
              <lucide-icon [img]="ArrowRightIcon" [size]="16" />
            </button>
            <button
              type="button"
              (click)="scrollTo('contact')"
              class="inline-flex cursor-pointer items-center gap-2 rounded-sm border border-zinc-700 px-6 py-3 text-sm font-semibold text-zinc-300 no-underline transition-all hover:border-zinc-500 hover:text-white hover:shadow-xs hover:shadow-zinc-800 active:scale-[0.98]"
            >
              <lucide-icon [img]="MailIcon" [size]="16" />
              Get In Touch
            </button>
          </div>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HeroSectionComponent {
  private readonly platformId = inject(PLATFORM_ID);

  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly Code2Icon = Code2;
  protected readonly MailIcon = Mail;

  protected scrollTo(id: string): void {
    if (isPlatformBrowser(this.platformId)) {
      document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
    }
  }
}
