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
import { LucideAngularModule, Code2 } from 'lucide-angular';
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
  protected readonly Code2Icon = Code2;

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
    if (!badge || !title || !subtitle) return;

    const tl = gsap.timeline({
      delay: 0.2,
      onComplete: () => {
        [badge, title, subtitle].forEach((el) => {
          (el as HTMLElement).removeAttribute('style');
        });
      },
    });

    const shared = { ease: 'power3.out' };
    tl.from(badge, { opacity: 0, y: 10, duration: 0.5, ...shared });
    tl.from(title, { opacity: 0, y: 14, duration: 0.55, ...shared }, '-=0.35');
    tl.from(
      subtitle,
      { opacity: 0, y: 10, duration: 0.5, ...shared },
      '-=0.35',
    );

    this.destroyRef.onDestroy(() => tl.kill());
  }
}
