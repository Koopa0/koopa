import { Component, ChangeDetectionStrategy } from '@angular/core';
import { LucideAngularModule, Server, Monitor, Cloud } from 'lucide-angular';
import type { LucideIconData } from 'lucide-angular';

interface TechCategory {
  name: string;
  icon: LucideIconData;
  items: string[];
}

@Component({
  selector: 'app-tech-stack',
  standalone: true,
  imports: [LucideAngularModule],
  template: `
    <section class="border-b border-zinc-800 bg-zinc-900/30">
      <div class="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8">
        <div class="mb-12 text-center">
          <h2 class="text-3xl font-bold text-zinc-100">Tech Stack</h2>
          <p class="mt-3 text-zinc-400">Technologies and tools I work with daily</p>
        </div>

        <div class="grid grid-cols-1 gap-8 md:grid-cols-3">
          @for (category of techCategories; track category.name) {
            <div class="rounded-sm border border-zinc-800 bg-zinc-900/50 p-6">
              <div class="mb-5 flex items-center gap-3">
                <div
                  class="flex h-9 w-9 items-center justify-center rounded-sm bg-zinc-800"
                >
                  <lucide-icon
                    [img]="category.icon"
                    [size]="18"
                    class="text-zinc-300"
                  />
                </div>
                <h3 class="text-sm font-semibold text-zinc-200">
                  {{ category.name }}
                </h3>
              </div>
              <div class="flex flex-wrap gap-2">
                @for (item of category.items; track item) {
                  <span
                    class="rounded-sm bg-zinc-800 px-2.5 py-1 text-sm text-zinc-300"
                  >
                    {{ item }}
                  </span>
                }
              </div>
            </div>
          }
        </div>
      </div>
    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TechStackComponent {
  protected readonly ServerIcon = Server;
  protected readonly MonitorIcon = Monitor;
  protected readonly CloudIcon = Cloud;

  protected readonly techCategories: TechCategory[] = [
    {
      name: 'Frontend',
      icon: this.MonitorIcon,
      items: ['Angular', 'Flutter'],
    },
    {
      name: 'Backend',
      icon: this.ServerIcon,
      items: ['Golang', 'Rust'],
    },
    {
      name: 'DevOps',
      icon: this.CloudIcon,
      items: ['Docker', 'Kubernetes'],
    },
  ];
}
