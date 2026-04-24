import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { LucideAngularModule, X as XIcon } from 'lucide-angular';
import {
  ENTITY_TYPE_META,
  type EntityTypeMeta,
  type InspectorTargetType,
} from '../../core/models/workbench.model';
import { InspectorService } from './inspector.service';
import { GoalInspectorComponent } from './renderers/goal-inspector/goal-inspector.component';
import { ProjectInspectorComponent } from './renderers/project-inspector/project-inspector.component';
import { ContentInspectorComponent } from './renderers/content-inspector/content-inspector.component';
import { HypothesisInspectorComponent } from './renderers/hypothesis-inspector/hypothesis-inspector.component';
import { TaskInspectorComponent } from './renderers/task-inspector/task-inspector.component';
import { TodoInspectorComponent } from './renderers/todo-inspector/todo-inspector.component';
import { AgentInspectorComponent } from './renderers/agent-inspector/agent-inspector.component';
import { ConceptInspectorComponent } from './renderers/concept-inspector/concept-inspector.component';
import { BookmarkInspectorComponent } from './renderers/bookmark-inspector/bookmark-inspector.component';

/**
 * Right-side inspector panel — structural template shared by all renderers.
 *
 * Structure: Header (type badge + title) → Tabs → Body → Action bar.
 * Tabs and actions are renderer-driven: the shell provides the chrome,
 * each renderer defines its own tab list and action bar.
 *
 * Mounted at layout level (sibling of `<router-outlet>`) so it survives
 * route switches. Visibility driven by InspectorService.
 */
@Component({
  selector: 'app-inspector-panel',
  standalone: true,
  imports: [
    LucideAngularModule,
    GoalInspectorComponent,
    ProjectInspectorComponent,
    ContentInspectorComponent,
    HypothesisInspectorComponent,
    TaskInspectorComponent,
    TodoInspectorComponent,
    AgentInspectorComponent,
    ConceptInspectorComponent,
    BookmarkInspectorComponent,
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
  protected readonly XIcon = XIcon;

  /**
   * Lookup entity metadata for a given type. Method form (not a field) so the
   * template's `[class]`/`{{ }}` bindings inside the `@if (...; as t)` scope
   * resolve against the component context consistently under the unit-test
   * builder's JIT compilation path.
   */
  protected meta(type: InspectorTargetType): EntityTypeMeta {
    return ENTITY_TYPE_META[type];
  }

  protected close(): void {
    this.inspector.close();
  }

  protected onEscape(): void {
    if (!this.isOpen()) return;

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
