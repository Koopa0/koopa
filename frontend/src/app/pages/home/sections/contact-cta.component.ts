import { Component, ChangeDetectionStrategy } from '@angular/core';
import {
  LucideAngularModule,
  Mail,
  Github,
  Linkedin,
  Twitter,
} from 'lucide-angular';
import type { LucideIconData } from 'lucide-angular';

interface SocialLink {
  name: string;
  url: string;
  icon: LucideIconData;
}

@Component({
  selector: 'app-contact-cta',
  standalone: true,
  imports: [LucideAngularModule],
  template: `
    <section id="contact" class="bg-zinc-900/50">
      <div class="mx-auto max-w-7xl px-4 py-20 text-center sm:px-6 lg:px-8">
        <h2 class="text-3xl font-bold text-zinc-100">
          Let's Build Something Together
        </h2>
        <p class="mx-auto mt-4 max-w-xl text-zinc-400">
          對合作有興趣、有技術問題想討論，或只是想打個招呼？歡迎隨時聯繫我。
        </p>
        <div class="mt-10 flex items-center justify-center gap-4">
          @for (link of socialLinks; track link.name) {
            <a
              [href]="link.url"
              target="_blank"
              rel="noopener noreferrer"
              [title]="link.name"
              class="flex h-11 w-11 items-center justify-center rounded-sm border border-zinc-700 text-zinc-400 no-underline transition-colors hover:border-zinc-500 hover:bg-zinc-800 hover:text-zinc-200"
            >
              <lucide-icon [img]="link.icon" [size]="18" />
            </a>
          }
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ContactCtaComponent {
  protected readonly MailIcon = Mail;
  protected readonly GithubIcon = Github;
  protected readonly LinkedinIcon = Linkedin;
  protected readonly TwitterIcon = Twitter;

  protected readonly socialLinks: SocialLink[] = [
    {
      name: 'Email',
      url: 'mailto:hello@koopa0.dev',
      icon: this.MailIcon,
    },
    {
      name: 'GitHub',
      url: 'https://github.com/koopa0',
      icon: this.GithubIcon,
    },
    {
      name: 'LinkedIn',
      url: 'https://linkedin.com/in/koopa0',
      icon: this.LinkedinIcon,
    },
    {
      name: 'X',
      url: 'https://x.com/koopa0',
      icon: this.TwitterIcon,
    },
  ];
}
