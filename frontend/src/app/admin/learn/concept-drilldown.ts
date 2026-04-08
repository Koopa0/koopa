import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, ArrowLeft, Brain } from 'lucide-angular';

@Component({
  selector: 'app-concept-drilldown',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    <div class="mx-auto max-w-3xl px-4 py-6 sm:px-6">
      <a
        routerLink="/admin/learn/dashboard"
        class="mb-6 inline-flex items-center gap-1.5 text-sm text-zinc-500 no-underline hover:text-zinc-300"
        data-testid="back-to-dashboard"
      >
        <lucide-icon [img]="ArrowLeftIcon" [size]="14" />
        返回學習儀表板
      </a>

      <div
        class="mt-8 flex flex-col items-center justify-center rounded-sm border border-dashed border-zinc-800 px-6 py-16 text-center"
      >
        <lucide-icon [img]="BrainIcon" [size]="32" class="mb-4 text-zinc-600" />
        <h1 class="text-lg font-semibold text-zinc-300 mb-2">
          Concept Detail — 建設中
        </h1>
        <p class="max-w-md text-sm text-zinc-500">
          概念詳情頁將顯示單一概念的學習歷程，包含歷史嘗試記錄、成功率趨勢、
          相關概念圖譜，以及 AI 觀察紀錄。
        </p>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ConceptDrilldownComponent {
  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly BrainIcon = Brain;
}
