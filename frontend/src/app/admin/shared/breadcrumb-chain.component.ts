import { Component, ChangeDetectionStrategy, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { LucideAngularModule, ChevronRight } from 'lucide-angular';

@Component({
  selector: 'app-breadcrumb-chain',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  template: `
    <nav class="flex items-center gap-1 text-sm" aria-label="breadcrumb">
      @for (item of items(); track item.label; let isLast = $last) {
        @if (item.route && !isLast) {
          <a
            [routerLink]="item.route"
            class="text-zinc-400 transition-colors hover:text-zinc-200"
          >
            {{ item.label }}
          </a>
        } @else {
          <span
            [class]="isLast ? 'text-zinc-100 font-medium' : 'text-zinc-400'"
          >
            {{ item.label }}
          </span>
        }
        @if (!isLast) {
          <lucide-icon
            [img]="ChevronRightIcon"
            [size]="14"
            class="shrink-0 text-zinc-600"
          />
        }
      }
    </nav>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BreadcrumbChainComponent {
  readonly items = input.required<{ label: string; route?: string }[]>();

  protected readonly ChevronRightIcon = ChevronRight;
}
