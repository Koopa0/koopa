import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import {
  LucideAngularModule,
  Mail,
  Github,
  Linkedin,
  Code,
  MapPin,
} from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';
import { environment } from '../../../environments/environment';
import { buildPersonSchema } from '../../core/services/seo/json-ld.util';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

interface Skill {
  category: string;
  items: string[];
}

const SKILLS: Skill[] = [
  {
    category: 'Backend',
    items: ['Golang', 'Rust'],
  },
  {
    category: 'Frontend',
    items: ['Angular', 'Flutter'],
  },
  {
    category: 'DevOps',
    items: ['Docker', 'Kubernetes', 'Cloud Native'],
  },
];

@Component({
  selector: 'app-about',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './about.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class AboutComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  protected readonly skills = SKILLS;

  protected readonly MailIcon = Mail;
  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
  protected readonly CodeIcon = Code;
  protected readonly MapPinIcon = MapPin;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'About',
      description: 'Koopa — Software Engineer. Go, Angular, and cloud-native technologies.',
      ogUrl: `${environment.siteUrl}/about`,
      ogType: 'profile',
      jsonLd: buildPersonSchema(),
    });
  }
}
