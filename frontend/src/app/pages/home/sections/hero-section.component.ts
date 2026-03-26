import {
  Component,
  ChangeDetectionStrategy,
  inject,
  PLATFORM_ID,
  afterNextRender,
  ElementRef,
  NgZone,
  DestroyRef,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { LucideAngularModule, ArrowRight, Code2, Mail } from 'lucide-angular';
import { SmoothScrollService } from '../../../core/services/smooth-scroll.service';
import { HeroCanvasComponent } from '../../../shared/components/hero-canvas/hero-canvas.component';

@Component({
  selector: 'app-hero-section',
  standalone: true,
  imports: [LucideAngularModule, HeroCanvasComponent],
  template: `
    <section class="relative overflow-hidden border-b border-zinc-800">
      <!-- Background layers -->
      <div class="absolute inset-0">
        <!-- CSS fallback (visible during SSR + before canvas loads) -->
        <div
          class="hero-bg absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-(--color-brand)/10 via-zinc-950 to-zinc-950"
        ></div>
        <!-- Canvas flow field (lazy loaded, overlays on top) -->
        @defer (on idle) {
          <app-hero-canvas class="absolute inset-0" />
        }
      </div>

      <div
        class="relative mx-auto max-w-7xl px-4 py-24 sm:px-6 sm:py-32 lg:px-8 lg:py-40"
      >
        <div class="max-w-3xl">
          <p
            class="hero-badge mb-4 inline-flex items-center gap-2 rounded-full border border-zinc-700 px-3 py-1 text-xs font-medium text-zinc-400"
          >
            <lucide-icon [img]="Code2Icon" [size]="12" />
            Go Backend Consultant
          </p>
          <h1
            class="hero-title font-display text-4xl font-bold tracking-tight text-zinc-100 sm:text-5xl lg:text-6xl"
          >
            Production systems that perform
            <span class="text-(--color-brand-light)">under pressure</span>
          </h1>
          <p
            class="hero-subtitle mt-6 max-w-2xl text-lg leading-relaxed text-zinc-400"
          >
            Backend architecture, performance optimization, and system design.
            Building production-grade services with Go — from diagnosis to
            delivery.
          </p>
          <div class="hero-cta mt-10 flex flex-wrap items-center gap-4">
            <button
              type="button"
              (click)="scrollToContact()"
              class="cta-primary group relative inline-flex cursor-pointer items-center gap-2 overflow-hidden rounded-sm bg-white px-6 py-3 text-sm font-semibold text-zinc-900 no-underline transition-all hover:scale-[1.02] hover:bg-zinc-200 active:scale-[0.98]"
            >
              Have a backend challenge? Let's talk
              <lucide-icon [img]="MailIcon" [size]="16" />
            </button>
            <a
              href="/projects/koopa0-dev"
              class="inline-flex cursor-pointer items-center gap-2 rounded-sm border border-zinc-700 px-6 py-3 text-sm font-semibold text-zinc-300 no-underline transition-all hover:border-zinc-500 hover:text-white hover:shadow-xs hover:shadow-zinc-800 active:scale-[0.98]"
            >
              See how this site was built
              <lucide-icon [img]="ArrowRightIcon" [size]="16" />
            </a>
          </div>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HeroSectionComponent {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly el = inject(ElementRef);
  private readonly ngZone = inject(NgZone);
  private readonly destroyRef = inject(DestroyRef);
  private readonly smoothScroll = inject(SmoothScrollService);

  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly Code2Icon = Code2;
  protected readonly MailIcon = Mail;

  constructor() {
    afterNextRender(() => {
      this.ngZone.runOutsideAngular(() => this.animateEntrance());
    });
  }

  private async animateEntrance(): Promise<void> {
    if (!isPlatformBrowser(this.platformId)) return;
    const prefersReduced = window.matchMedia(
      '(prefers-reduced-motion: reduce)',
    ).matches;
    if (prefersReduced) return;

    const { gsap } = await import('../../../shared/utils/gsap');
    const root = this.el.nativeElement as HTMLElement;

    const badge = root.querySelector('.hero-badge');
    const title = root.querySelector('.hero-title');
    const subtitle = root.querySelector('.hero-subtitle');
    const cta = root.querySelector('.hero-cta');

    if (!badge || !title || !subtitle || !cta) return;

    const tl = gsap.timeline({
      delay: 0.2,
      onComplete: () => {
        // Remove all inline styles GSAP added so elements return to their CSS state
        [badge, title, subtitle, ...Array.from(buttons)].forEach((el) => {
          (el as HTMLElement).removeAttribute('style');
        });
      },
    });

    const buttons = cta.querySelectorAll('button, a');

    const shared = { ease: 'power3.out' };
    tl.from(badge, { opacity: 0, y: 10, duration: 0.5, ...shared });
    tl.from(title, { opacity: 0, y: 14, duration: 0.55, ...shared }, '-=0.35');
    tl.from(
      subtitle,
      { opacity: 0, y: 10, duration: 0.5, ...shared },
      '-=0.35',
    );
    tl.from(
      buttons,
      { opacity: 0, y: 6, duration: 0.1, stagger: 0.05, ...shared },
      '-=0.7',
    );

    this.destroyRef.onDestroy(() => tl.kill());
  }

  protected scrollToContact(): void {
    this.smoothScroll.scrollTo('#contact', { duration: 1.4 });
  }
}
