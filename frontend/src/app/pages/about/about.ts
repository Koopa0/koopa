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
  Wrench,
  Mail,
  Github,
  Linkedin,
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
      title: 'About',
      description: 'Koopa — Backend Engineer / Full-Stack Developer. Go, Angular, and cloud-native technologies.',
      ogUrl: 'https://koopa0.dev/about',
      ogType: 'profile',
      jsonLd: buildPersonSchema(),
    });
  }

  protected readonly CodeIcon = Code;
  protected readonly ServerIcon = Server;
  protected readonly WrenchIcon = Wrench;
  protected readonly MailIcon = Mail;
  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
  protected readonly skills: SkillGroup[] = [
    {
      category: 'Backend',
      icon: this.ServerIcon,
      items: ['Golang', 'Rust'],
    },
    {
      category: 'Frontend',
      icon: this.CodeIcon,
      items: ['Angular', 'Flutter'],
    },
    {
      category: 'DevOps',
      icon: this.WrenchIcon,
      items: ['Docker', 'Kubernetes', 'Cloud Native'],
    },
  ];
}
