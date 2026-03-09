import {
  Component,
  ChangeDetectionStrategy,
  inject,
} from '@angular/core';
import {
  LucideAngularModule,
  Monitor,
  Terminal,
  Package,
  Wrench,
} from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';
import { fadeInUp } from '../../shared/animations/fade-in.animation';

interface UseItem {
  name: string;
  description: string;
  url?: string;
}

interface UseCategory {
  title: string;
  icon: typeof Terminal;
  items: UseItem[];
}

const USE_CATEGORIES: UseCategory[] = [
  {
    title: 'Editor & Terminal',
    icon: Terminal,
    items: [
      { name: 'Neovim', description: 'Primary editor with LazyVim config' },
      { name: 'WezTerm', description: 'GPU-accelerated terminal emulator' },
      { name: 'tmux', description: 'Terminal multiplexer for session management' },
      { name: 'Zsh', description: 'Shell with Oh My Zsh' },
    ],
  },
  {
    title: 'Development',
    icon: Package,
    items: [
      { name: 'Go', description: 'Backend services, CLI tools' },
      { name: 'Angular', description: 'Frontend framework of choice' },
      { name: 'Rust', description: 'Systems programming, performance-critical tools' },
      { name: 'Flutter', description: 'Cross-platform mobile apps' },
      { name: 'Docker', description: 'Containerized development and deployment' },
      { name: 'PostgreSQL', description: 'Primary database' },
    ],
  },
  {
    title: 'Hardware',
    icon: Monitor,
    items: [
      { name: 'MacBook Pro', description: 'Primary development machine' },
    ],
  },
  {
    title: 'Productivity',
    icon: Wrench,
    items: [
      { name: 'Obsidian', description: 'Knowledge management and note-taking' },
      { name: 'Linear', description: 'Project and issue tracking' },
      { name: 'Figma', description: 'UI/UX design' },
      { name: 'Claude', description: 'AI-assisted development' },
    ],
  },
];

@Component({
  selector: 'app-uses',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './uses.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class UsesComponent {
  private readonly seoService = inject(SeoService);

  protected readonly categories = USE_CATEGORIES;
  protected readonly WrenchIcon = Wrench;

  constructor() {
    this.seoService.updateMeta({
      title: 'Uses',
      description: 'Tools, hardware, and software I use for development.',
      ogUrl: 'https://koopa0.dev/uses',
    });
  }
}
