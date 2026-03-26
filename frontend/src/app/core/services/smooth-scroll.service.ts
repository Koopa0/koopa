import {
  Injectable,
  inject,
  NgZone,
  PLATFORM_ID,
  OnDestroy,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

@Injectable({ providedIn: 'root' })
export class SmoothScrollService implements OnDestroy {
  private readonly ngZone = inject(NgZone);
  private readonly platformId = inject(PLATFORM_ID);
  private lenis: import('lenis').default | null = null;
  private rafId = 0;
  private initialized = false;

  async init(): Promise<void> {
    if (this.initialized || !isPlatformBrowser(this.platformId)) return;
    this.initialized = true;

    const [{ default: Lenis }, { gsap, ScrollTrigger, registerGsapPlugins }] =
      await Promise.all([import('lenis'), import('../../shared/utils/gsap')]);

    registerGsapPlugins();

    this.ngZone.runOutsideAngular(() => {
      this.lenis = new Lenis({
        duration: 1.2,
        easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
        touchMultiplier: 2,
      });

      this.lenis.on('scroll', ScrollTrigger.update);

      gsap.ticker.add((time: number) => {
        this.lenis?.raf(time * 1000);
      });

      gsap.ticker.lagSmoothing(0);
    });
  }

  scrollTo(
    target: string | number | HTMLElement,
    options?: { offset?: number; duration?: number },
  ): void {
    this.lenis?.scrollTo(target, {
      offset: options?.offset ?? 0,
      duration: options?.duration ?? 1.2,
    });
  }

  stop(): void {
    this.lenis?.stop();
  }

  start(): void {
    this.lenis?.start();
  }

  ngOnDestroy(): void {
    this.lenis?.destroy();
    this.lenis = null;
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
    }
  }
}
