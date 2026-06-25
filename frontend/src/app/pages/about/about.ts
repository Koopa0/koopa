import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  ElementRef,
  OnInit,
  afterNextRender,
  inject,
  signal,
  viewChild,
  viewChildren,
} from '@angular/core';
import { DOCUMENT } from '@angular/common';
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
 * About — the colophon. The two-rail `.ed-spread` (mono rail + serif column)
 * that the article-detail surface uses, so About reads at the weight of a
 * written piece: statement + prose + pull + a dated NOW + two definition lists
 * (Elsewhere, Colophon) + a signature.
 *
 * The "alive" layer is progressive enhancement, browser-only via afterNextRender:
 * a scroll-spy that lights the rail jump-link for the section in view, and a
 * scroll reveal of each block. The reveal is gated by the `.ed-about-anim` class
 * (added here, in the browser) so under SSR / no-JS the content is fully visible
 * and never hidden by CSS alone. Above-fold blocks reveal synchronously in the
 * same frame, so there is no hide-then-show flash.
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
  private readonly doc = inject(DOCUMENT);

  /** The `.ed-spread` container — gets `.ed-about-anim` only in the browser. */
  private readonly spread = viewChild.required<ElementRef<HTMLElement>>('spread');
  /** The four labelled blocks (scroll-spy + reveal targets). */
  private readonly blocks = viewChildren<ElementRef<HTMLElement>>('block');

  /** The section currently in view — drives the rail highlight. */
  protected readonly activeSection = signal('statement');

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
      // reaches here); we also bail where IntersectionObserver is unavailable, so
      // the content always renders fully without these effects.
      if (typeof IntersectionObserver === 'undefined') {
        return;
      }

      const elements = this.blocks().map((b) => b.nativeElement);

      // Scroll-spy: light the rail link for the section crossing the middle
      // band. A colour change, not motion — runs even under reduced motion.
      const spy = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            const id = entry.target.getAttribute('id');
            if (entry.isIntersecting && id) {
              this.activeSection.set(id);
            }
          }
        },
        { rootMargin: '-35% 0px -55% 0px' },
      );
      for (const el of elements) {
        spy.observe(el);
      }

      const reduced =
        typeof window.matchMedia === 'function' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      // Scroll reveal — this is motion, so it is gated at the source for
      // reduced-motion users (the CSS media rule is the belt-and-suspenders).
      let reveal: IntersectionObserver | undefined;
      if (!reduced) {
        this.spread().nativeElement.classList.add('ed-about-anim');

        // Reveal whatever is already on screen in this frame — no hidden flash.
        const fold = window.innerHeight * 0.9;
        for (const el of elements) {
          if (el.getBoundingClientRect().top < fold) {
            el.classList.add('is-in');
          }
        }

        reveal = new IntersectionObserver(
          (entries) => {
            for (const entry of entries) {
              if (entry.isIntersecting) {
                entry.target.classList.add('is-in');
                reveal?.unobserve(entry.target);
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
      }

      this.destroyRef.onDestroy(() => {
        spy.disconnect();
        reveal?.disconnect();
      });
    });
  }

  /** Smooth-scroll to a section. A click handler (not a bare `#` href) so the
   *  router never treats the fragment as a navigation. */
  protected jump(event: Event, id: string): void {
    event.preventDefault();
    this.doc.getElementById(id)?.scrollIntoView({
      behavior: 'smooth',
      block: 'start',
    });
    this.activeSection.set(id);
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
