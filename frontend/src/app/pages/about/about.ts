import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import {
  LucideAngularModule,
  Code,
  Server,
  Smartphone,
  Wrench,
  Mail,
  Github,
  Linkedin,
  Twitter,
} from 'lucide-angular';
import type { LucideIconData } from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildPersonSchema } from '../../core/services/seo/json-ld.util';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

interface SkillGroup {
  category: string;
  icon: LucideIconData;
  items: string[];
}

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
  ngOnInit(): void {
    this.seoService.updateMeta({
      title: '關於我',
      description: 'Backend Engineer / Full-Stack Developer，熱愛技術與開源',
      ogUrl: 'https://koopa0.dev/about',
      ogType: 'profile',
      jsonLd: buildPersonSchema(),
    });
  }

  protected readonly CodeIcon = Code;
  protected readonly ServerIcon = Server;
  protected readonly SmartphoneIcon = Smartphone;
  protected readonly WrenchIcon = Wrench;
  protected readonly MailIcon = Mail;
  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
  protected readonly TwitterIcon = Twitter;

  protected readonly skills: SkillGroup[] = [
    {
      category: '前端開發',
      icon: this.CodeIcon,
      items: ['Angular', 'Flutter'],
    },
    {
      category: '後端開發',
      icon: this.ServerIcon,
      items: ['Golang', 'Rust'],
    },
    {
      category: '行動開發',
      icon: this.SmartphoneIcon,
      items: ['Flutter'],
    },
    {
      category: '開發工具',
      icon: this.WrenchIcon,
      items: ['Docker', 'Kubernetes'],
    },
  ];
}
