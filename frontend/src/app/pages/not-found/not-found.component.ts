import {
  Component,
  ChangeDetectionStrategy,
  OnInit,
  inject,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, Home, FileText, User } from 'lucide-angular';
import { SeoService } from '../../core/services/seo/seo.service';

@Component({
  selector: 'app-not-found',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    <section
      class="flex min-h-[calc(100vh-4rem)] items-center justify-center bg-zinc-950 px-4"
    >
      <div class="text-center">
        <p class="text-8xl font-bold text-zinc-800">404</p>
        <h1 class="mt-4 text-2xl font-bold text-zinc-100">找不到頁面</h1>
        <p class="mt-2 text-sm text-zinc-400">您要尋找的頁面不存在或已被移除</p>
        <div class="mt-8 flex flex-wrap items-center justify-center gap-3">
          <a
            routerLink="/home"
            class="inline-flex items-center gap-2 rounded-sm bg-white px-5 py-2.5 text-sm font-semibold text-zinc-900 no-underline transition-colors hover:bg-zinc-200"
          >
            <lucide-icon [img]="HomeIcon" [size]="16" />
            回到首頁
          </a>
          <a
            routerLink="/articles"
            class="inline-flex items-center gap-2 rounded-sm border border-zinc-700 px-5 py-2.5 text-sm text-zinc-300 no-underline transition-colors hover:border-zinc-500 hover:text-white"
          >
            <lucide-icon [img]="FileTextIcon" [size]="16" />
            瀏覽文章
          </a>
          <a
            routerLink="/about"
            class="inline-flex items-center gap-2 rounded-sm border border-zinc-700 px-5 py-2.5 text-sm text-zinc-300 no-underline transition-colors hover:border-zinc-500 hover:text-white"
          >
            <lucide-icon [img]="UserIcon" [size]="16" />
            關於我
          </a>
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NotFoundComponent implements OnInit {
  private readonly seoService = inject(SeoService);

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: '404 - 找不到頁面',
      description: '您要尋找的頁面不存在或已被移除',
      noIndex: true,
    });
  }

  protected readonly HomeIcon = Home;
  protected readonly FileTextIcon = FileText;
  protected readonly UserIcon = User;
}
