import {
  ChangeDetectionStrategy,
  Component,
  inject,
  signal,
} from '@angular/core';
import { LucideAngularModule, X as XIcon } from 'lucide-angular';
import { InspectorService } from './inspector.service';
import { GoalInspectorComponent } from './renderers/goal-inspector/goal-inspector.component';
import { ProjectInspectorComponent } from './renderers/project-inspector/project-inspector.component';
import type { InspectorTab } from './renderers/goal-inspector/goal-inspector.component';

/**
 * Right-side panel that renders the active inspector for the currently
 * selected entity. Mounted as a sibling of <router-outlet> at layout level
 * so it survives mode/route switches.
 *
 * Tab state lives locally — there is no need to sync it to the URL since
 * tabs are a UX detail, not a shareable surface. Inspector visibility is
 * driven entirely by InspectorService (which reads from `?inspect=`).
 */
@Component({
  selector: 'app-inspector-panel',
  standalone: true,
  imports: [
    LucideAngularModule,
    GoalInspectorComponent,
    ProjectInspectorComponent,
  ],
  templateUrl: './inspector-panel.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    '(document:keydown.escape)': 'onEscape()',
  },
})
export class InspectorPanelComponent {
  protected readonly inspector = inject(InspectorService);
  protected readonly target = this.inspector.target;
  protected readonly isOpen = this.inspector.isOpen;

  protected readonly activeTab = signal<InspectorTab>('overview');

  protected readonly XIcon = XIcon;

  protected setTab(tab: InspectorTab): void {
    this.activeTab.set(tab);
  }

  protected close(): void {
    this.inspector.close();
  }

  protected onEscape(): void {
    if (!this.isOpen()) return;

    // Don't intercept Esc when focus is in a form control. Use
    // document.activeElement instead of event.target so we don't have to
    // type the host binding's $event (Angular widens it to Event in the
    // template type-checker).
    const active = document.activeElement;
    if (
      active instanceof HTMLInputElement ||
      active instanceof HTMLTextAreaElement ||
      active instanceof HTMLSelectElement ||
      (active instanceof HTMLElement && active.isContentEditable)
    ) {
      return;
    }

    this.close();
  }
}
