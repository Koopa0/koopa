import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  ElementRef,
  OnInit,
  afterNextRender,
  inject,
  viewChild,
  viewChildren,
} from '@angular/core';
import { LucideAngularModule, Github, Linkedin, Mail } from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';
import { buildPersonSchema } from '../../core/services/seo/json-ld.util';

interface DefRow {
  term: string;
  value: string;
}

type LinkKind = 'github' | 'linkedin' | 'x' | 'email';

interface LinkRow extends DefRow {
  href: string;
  kind: LinkKind;
}

/**
 * About — the colophon. A single serif column: statement + prose + pull + a
 * dated NOW + two definition lists (Elsewhere, Colophon) + a signature. Reads
 * at the weight of a written piece.
 *
 * The "alive" layer is progressive enhancement, browser-only via afterNextRender:
 * each block scroll-reveals as it enters view, gated by the `.ed-about-anim`
 * class (added here, in the browser) so under SSR / no-JS the content is fully
 * visible and never hidden by CSS alone. Above-fold blocks reveal synchronously
 * in the same frame, so there is no hide-then-show flash. Honored at the source
 * for reduced-motion users.
 */
@Component({
  selector: 'app-about',
  imports: [LucideAngularModule],
  templateUrl: './about.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AboutComponent implements OnInit {
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  /** The column — gets `.ed-about-anim` only in the browser. */
  private readonly column = viewChild.required<ElementRef<HTMLElement>>('column');
  /** The labelled blocks (reveal targets). */
  private readonly blocks = viewChildren<ElementRef<HTMLElement>>('block');

  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
  protected readonly MailIcon = Mail;

  /** Last hand-edit of the NOW block — the /now liveness stamp. */
  protected readonly nowUpdated = 'June 25, 2026';

  /** The page's single strong line (an owner slot he may refine). */
  protected readonly statement = 'I build systems, and write down what I work out.';

  /** Colophon stack — known from the repository, safe to state. */
  protected readonly stack: readonly DefRow[] = [
    { term: 'Built with', value: 'Go · PostgreSQL · pgvector' },
    { term: 'Interface', value: 'Angular · Tailwind · SSR' },
    { term: 'Knowledge', value: 'MCP · AI agents' },
  ];

  /** Contacts — the real links carried over from the prior about page. */
  protected readonly elsewhere: readonly LinkRow[] = [
    {
      term: 'GitHub',
      value: 'github.com/koopa0',
      href: 'https://github.com/koopa0',
      kind: 'github',
    },
    {
      term: 'LinkedIn',
      value: 'Koopa Chen',
      href: 'https://www.linkedin.com/in/koopa-chen-70a4651ba/',
      kind: 'linkedin',
    },
    {
      term: 'X',
      value: '@Koopa012426',
      href: 'https://x.com/Koopa012426',
      kind: 'x',
    },
    {
      term: 'Email',
      value: 'contact@koopa0.dev',
      href: 'mailto:contact@koopa0.dev',
      kind: 'email',
    },
  ];

  constructor() {
    afterNextRender(() => {
      // Progressive enhancement only. afterNextRender is browser-only (SSR never
      // reaches here); we also bail where IntersectionObserver is unavailable or
      // the user prefers reduced motion, so the content always renders fully.
      if (typeof IntersectionObserver === 'undefined') {
        return;
      }
      const reduced =
        typeof window.matchMedia === 'function' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (reduced) {
        return;
      }

      this.column().nativeElement.classList.add('ed-about-anim');
      const elements = this.blocks().map((b) => b.nativeElement);

      // Reveal whatever is already on screen in this frame — no hidden flash.
      const fold = window.innerHeight * 0.9;
      for (const el of elements) {
        if (el.getBoundingClientRect().top < fold) {
          el.classList.add('is-in');
        }
      }

      // Reveal the rest as they scroll into view (once each).
      const reveal = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if (entry.isIntersecting) {
              entry.target.classList.add('is-in');
              reveal.unobserve(entry.target);
            }
          }
        },
        { rootMargin: '0px 0px -10% 0px' },
      );
      for (const el of elements) {
        if (!el.classList.contains('is-in')) {
          reveal.observe(el);
        }
      }

      this.destroyRef.onDestroy(() => reveal.disconnect());
    });
  }

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'About',
      description:
        'Koopa — Software Engineer. Go, Angular, and cloud-native technologies.',
      ogUrl: `${environment.siteUrl}/about`,
      ogType: 'profile',
      jsonLd: buildPersonSchema(),
    });
  }
}
