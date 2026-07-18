import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
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
 * About — the colophon. A single centered serif reading column: a statement, one
 * kintsugi seam, three prose paragraphs, an italic pull line, a dated NOW block
 * (with a quiet breathing pip), a mono colophon <dl> + signature, and a tiny mono
 * "elsewhere" links row. Reads at the weight of a written piece.
 *
 * The load-in is pure CSS: every block carries the shared `.ed-rise` orchestration
 * class, whose keyframes live behind `prefers-reduced-motion: no-preference`. So
 * the SSR / no-JS / reduced-motion state is the fully-visible content — nothing is
 * ever hidden by CSS alone, and there is no JavaScript reveal or IntersectionObserver.
 */
@Component({
  selector: 'app-about',
  imports: [LucideAngularModule],
  templateUrl: './about.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AboutComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
  protected readonly MailIcon = Mail;

  /** Last hand-edit of the NOW block — the /now liveness stamp. */
  protected readonly nowUpdated = 'June 25, 2026';

  /** The page's single strong line (an owner slot he may refine). */
  protected readonly statement = 'I build systems, and write down what I work out.';

  /** Colophon stack — known from the repository, safe to state. */
  protected readonly stack: readonly DefRow[] = [
    { term: 'Built with', value: 'Go · PostgreSQL' },
    { term: 'Interface', value: 'Angular · Tailwind · SSR' },
    { term: 'Tools', value: 'MCP · AI agents' },
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
