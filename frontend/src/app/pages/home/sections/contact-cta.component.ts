import { Component, ChangeDetectionStrategy } from '@angular/core';
import {
  LucideAngularModule,
  Mail,
  Github,
  Linkedin,
} from 'lucide-angular';
import type { LucideIconData } from 'lucide-angular';

interface SocialLink {
  name: string;
  url: string;
  icon?: LucideIconData;
  isX?: boolean;
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
          Interested in collaboration, have a technical question, or just want to say hi? Feel free to reach out.
        </p>
        <div class="mt-10 flex items-center justify-center gap-4">
          @for (link of socialLinks; track link.name) {
            <a
              [href]="link.url"
              target="_blank"
              rel="noopener noreferrer"
              [title]="link.name"
              class="flex size-11 items-center justify-center rounded-sm border border-zinc-700 text-zinc-400 no-underline transition-colors hover:border-zinc-500 hover:bg-zinc-800 hover:text-zinc-200"
            >
              @if (link.isX) {
                <svg class="size-[18px]" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              } @else {
                <lucide-icon [img]="link.icon!" [size]="18" />
              }
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

  protected readonly socialLinks: SocialLink[] = [
    {
      name: 'Email',
      url: 'mailto:contact@koopa0.dev',
      icon: this.MailIcon,
    },
    {
      name: 'GitHub',
      url: 'https://github.com/koopa0',
      icon: this.GithubIcon,
    },
    {
      name: 'LinkedIn',
      url: 'https://www.linkedin.com/in/koopa-chen-70a4651ba/',
      icon: this.LinkedinIcon,
    },
    {
      name: 'X',
      url: 'https://x.com/Koopa012426',
      isX: true,
    },
  ];
}
