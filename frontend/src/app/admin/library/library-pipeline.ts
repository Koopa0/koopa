import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  PenLine,
  FileText,
  Eye,
  Send,
  ChevronRight,
} from 'lucide-angular';

@Component({
  selector: 'app-library-pipeline',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    <div class="mx-auto max-w-4xl px-4 py-6 sm:px-6">
      <div class="mb-6">
        <h1 class="text-lg font-semibold text-zinc-100">Content Pipeline</h1>
        <p class="text-sm text-zinc-500">內容工作流程：草稿 → 審核 → 發佈</p>
      </div>

      <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        @for (
          stage of [
            {
              label: '草稿進行中',
              icon: PenLineIcon,
              count: 3,
              color: 'amber'
            },
            { label: '審核中', icon: EyeIcon, count: 1, color: 'sky' },
            { label: '待發佈', icon: SendIcon, count: 2, color: 'emerald' },
            { label: '已發佈', icon: FileTextIcon, count: 12, color: 'zinc' }
          ];
          track stage.label
        ) {
          <div class="rounded-sm border border-zinc-800 bg-zinc-900/50 p-4">
            <div class="flex items-center gap-2 mb-3">
              <lucide-icon
                [img]="stage.icon"
                [size]="16"
                class="text-zinc-400"
              />
              <span class="text-xs font-medium text-zinc-400">{{
                stage.label
              }}</span>
              <span class="ml-auto text-lg font-semibold text-zinc-200">{{
                stage.count
              }}</span>
            </div>
            <div
              class="rounded-sm border border-dashed border-zinc-800 px-3 py-6 text-center text-xs text-zinc-600"
            >
              內容清單建設中
            </div>
          </div>
        }
      </div>

      <div class="mt-6 text-center">
        <a
          routerLink="/admin/library/contents"
          class="inline-flex items-center gap-1 text-sm text-zinc-500 no-underline hover:text-zinc-300"
        >
          查看所有內容
          <lucide-icon [img]="ChevronRightIcon" [size]="14" />
        </a>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LibraryPipelineComponent {
  protected readonly PenLineIcon = PenLine;
  protected readonly FileTextIcon = FileText;
  protected readonly EyeIcon = Eye;
  protected readonly SendIcon = Send;
  protected readonly ChevronRightIcon = ChevronRight;
}
