import {
  Component,
  ChangeDetectionStrategy,
  inject,
  ElementRef,
  NgZone,
  PLATFORM_ID,
  DestroyRef,
  afterNextRender,
  viewChild,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

// --- Aurora band configuration ---

interface AuroraBand {
  yBase: number;
  amplitude: number;
  wavelength: number;
  speed: number;
  phaseOffset: number;
  color: string;
  opacity: number;
  width: number;
}

const BRAND_H = 245;

function createBands(height: number): AuroraBand[] {
  return [
    {
      yBase: height * 0.25,
      amplitude: height * 0.08,
      wavelength: 0.003,
      speed: 0.4,
      phaseOffset: 0,
      color: `oklch(0.58 0.2 ${BRAND_H})`,
      opacity: 0.12,
      width: height * 0.18,
    },
    {
      yBase: height * 0.35,
      amplitude: height * 0.1,
      wavelength: 0.0025,
      speed: 0.3,
      phaseOffset: 2,
      color: `oklch(0.52 0.16 ${BRAND_H + 15})`,
      opacity: 0.08,
      width: height * 0.22,
    },
    {
      yBase: height * 0.2,
      amplitude: height * 0.06,
      wavelength: 0.004,
      speed: 0.55,
      phaseOffset: 4.5,
      color: `oklch(0.65 0.14 ${BRAND_H - 10})`,
      opacity: 0.06,
      width: height * 0.15,
    },
    {
      yBase: height * 0.4,
      amplitude: height * 0.12,
      wavelength: 0.002,
      speed: 0.2,
      phaseOffset: 1.2,
      color: `oklch(0.45 0.12 ${BRAND_H + 25})`,
      opacity: 0.05,
      width: height * 0.25,
    },
  ];
}

@Component({
  selector: 'app-hero-canvas',
  standalone: true,
  template: `<canvas #canvas class="size-full"></canvas>`,
  host: { class: 'block size-full' },
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class HeroCanvasComponent {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly ngZone = inject(NgZone);
  private readonly destroyRef = inject(DestroyRef);
  private readonly canvasRef =
    viewChild.required<ElementRef<HTMLCanvasElement>>('canvas');

  private ctx: CanvasRenderingContext2D | null = null;
  private bands: AuroraBand[] = [];
  private mouseX = 0.5;
  private mouseY = 0.5;
  private targetMouseX = 0.5;
  private targetMouseY = 0.5;
  private time = 0;
  private width = 0;
  private height = 0;
  private dpr = 1;
  private running = false;

  constructor() {
    afterNextRender(() => {
      if (!isPlatformBrowser(this.platformId)) return;

      const cores = navigator.hardwareConcurrency ?? 4;
      const prefersReduced = window.matchMedia(
        '(prefers-reduced-motion: reduce)',
      ).matches;
      if (cores <= 2 || prefersReduced) return;

      this.ngZone.runOutsideAngular(() => this.init());
    });
  }

  private init(): void {
    const canvas = this.canvasRef().nativeElement;
    this.ctx = canvas.getContext('2d', { alpha: true });
    if (!this.ctx) return;

    this.dpr = Math.min(window.devicePixelRatio, 2);
    this.resize();
    this.bands = createBands(this.height);
    this.bindEvents(canvas);
    this.running = true;
    this.animate();

    this.destroyRef.onDestroy(() => this.destroy());
  }

  private resize(): void {
    const canvas = this.canvasRef().nativeElement;
    const rect = canvas.parentElement?.getBoundingClientRect();
    if (!rect) return;
    this.width = rect.width;
    this.height = rect.height;
    canvas.width = this.width * this.dpr;
    canvas.height = this.height * this.dpr;
    canvas.style.width = `${this.width}px`;
    canvas.style.height = `${this.height}px`;
    this.ctx?.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    this.bands = createBands(this.height);
  }

  private bindEvents(canvas: HTMLCanvasElement): void {
    const onMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      this.targetMouseX = (e.clientX - rect.left) / this.width;
      this.targetMouseY = (e.clientY - rect.top) / this.height;
    };
    const onResize = () => this.resize();

    canvas.addEventListener('mousemove', onMove, { passive: true });
    window.addEventListener('resize', onResize, { passive: true });

    this.destroyRef.onDestroy(() => {
      canvas.removeEventListener('mousemove', onMove);
      window.removeEventListener('resize', onResize);
    });
  }

  private animate(): void {
    if (!this.running || !this.ctx) return;

    const ctx = this.ctx;
    this.time += 0.008;

    // Smooth mouse follow
    this.mouseX += (this.targetMouseX - this.mouseX) * 0.03;
    this.mouseY += (this.targetMouseY - this.mouseY) * 0.03;

    // Clear
    ctx.clearRect(0, 0, this.width, this.height);

    // Draw each aurora band
    for (const band of this.bands) {
      this.drawBand(ctx, band);
    }

    requestAnimationFrame(() => this.animate());
  }

  private drawBand(ctx: CanvasRenderingContext2D, band: AuroraBand): void {
    const steps = Math.ceil(this.width / 3);
    const stepSize = this.width / steps;

    // Mouse influence on the band
    const mouseDistort = (this.mouseX - 0.5) * band.amplitude * 0.6;
    const mouseVertical = (this.mouseY - 0.5) * band.amplitude * 0.3;

    ctx.beginPath();

    // Top edge of the band
    for (let i = 0; i <= steps; i++) {
      const x = i * stepSize;
      const xNorm = x / this.width;

      // Composite wave: primary + secondary harmonic + mouse
      const wave1 = Math.sin(
        x * band.wavelength + this.time * band.speed + band.phaseOffset,
      );
      const wave2 =
        Math.sin(
          x * band.wavelength * 2.3 +
            this.time * band.speed * 0.7 +
            band.phaseOffset * 1.5,
        ) * 0.3;
      const wave3 =
        Math.sin(x * band.wavelength * 0.5 + this.time * band.speed * 1.3) *
        0.2;

      // Fade edges horizontally
      const edgeFade = Math.sin(xNorm * Math.PI);
      const y =
        band.yBase +
        (wave1 + wave2 + wave3) * band.amplitude * edgeFade +
        mouseDistort * edgeFade +
        mouseVertical;

      if (i === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    }

    // Bottom edge (reverse, offset by band width)
    for (let i = steps; i >= 0; i--) {
      const x = i * stepSize;
      const xNorm = x / this.width;

      const wave1 = Math.sin(
        x * band.wavelength * 0.8 +
          this.time * band.speed * 0.6 +
          band.phaseOffset +
          1,
      );
      const wave2 =
        Math.sin(
          x * band.wavelength * 1.8 +
            this.time * band.speed * 0.4 +
            band.phaseOffset * 0.8,
        ) * 0.25;

      const edgeFade = Math.sin(xNorm * Math.PI);
      const y =
        band.yBase +
        band.width +
        (wave1 + wave2) * band.amplitude * 0.5 * edgeFade +
        mouseDistort * edgeFade * 0.3 +
        mouseVertical;

      ctx.lineTo(x, y);
    }

    ctx.closePath();

    // Gradient fill from center outward (vertically)
    const gradient = ctx.createLinearGradient(
      0,
      band.yBase - band.amplitude,
      0,
      band.yBase + band.width + band.amplitude,
    );
    gradient.addColorStop(0, 'transparent');
    gradient.addColorStop(0.3, band.color);
    gradient.addColorStop(0.5, band.color);
    gradient.addColorStop(0.7, band.color);
    gradient.addColorStop(1, 'transparent');

    ctx.fillStyle = gradient;
    ctx.globalAlpha = band.opacity;
    ctx.globalCompositeOperation = 'screen';
    ctx.filter = `blur(${band.width * 0.15}px)`;
    ctx.fill();

    // Reset
    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = 'source-over';
    ctx.filter = 'none';
  }

  private destroy(): void {
    this.running = false;
    this.ctx = null;
  }
}
