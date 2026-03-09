import {
  Component,
  ChangeDetectionStrategy,
  inject,
} from '@angular/core';
import {
  LucideAngularModule,
  Briefcase,
  GraduationCap,
  Code,
  ExternalLink,
  MapPin,
  Mail,
} from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

interface Experience {
  company: string;
  role: string;
  period: string;
  location: string;
  highlights: string[];
}

interface Skill {
  category: string;
  items: string[];
}

const EXPERIENCES: Experience[] = [
  {
    company: 'Company Name',
    role: 'Software Engineer',
    period: '2023 - Present',
    location: 'Taipei, Taiwan',
    highlights: [
      'Built scalable microservices with Go and gRPC',
      'Developed Angular 21 applications with SSR',
      'Maintained CI/CD pipelines with GitHub Actions',
    ],
  },
];

const SKILLS: Skill[] = [
  {
    category: 'Languages',
    items: ['Go', 'TypeScript', 'Rust', 'Dart', 'Python'],
  },
  {
    category: 'Frontend',
    items: ['Angular', 'Tailwind CSS', 'RxJS', 'Flutter'],
  },
  {
    category: 'Backend',
    items: ['Go (net/http, Gin)', 'PostgreSQL', 'Redis', 'gRPC'],
  },
  {
    category: 'DevOps',
    items: ['Docker', 'Kubernetes', 'GitHub Actions', 'GCP'],
  },
];

const EDUCATION = [
  {
    school: 'University Name',
    degree: 'Bachelor of Computer Science',
    period: '2019 - 2023',
  },
];

@Component({
  selector: 'app-resume',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './resume.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class ResumeComponent {
  private readonly seoService = inject(SeoService);

  protected readonly experiences = EXPERIENCES;
  protected readonly skills = SKILLS;
  protected readonly education = EDUCATION;

  protected readonly BriefcaseIcon = Briefcase;
  protected readonly GraduationCapIcon = GraduationCap;
  protected readonly CodeIcon = Code;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly MapPinIcon = MapPin;
  protected readonly MailIcon = Mail;

  constructor() {
    this.seoService.updateMeta({
      title: 'Resume',
      description: 'Koopa — Software Engineer. Go, Angular, Rust, Flutter.',
      ogUrl: 'https://koopa0.dev/resume',
    });
  }
}
