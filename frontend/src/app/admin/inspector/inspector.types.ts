import type { InspectorTargetType } from '../../core/models/workbench.model';

/**
 * Discriminated union of inspectable entities.
 *
 * All 10 renderers active:
 *   content, hypothesis, task, goal, project, note, todo, agent, concept, bookmark
 *
 * Each entity's design brief lives in frontend/docs/inspector-design/<entity>.md
 * — workflow: auggie semantic dive → WebSearch reference designs → lens collision → brief → ship.
 */
export interface InspectorTarget {
  type: InspectorTargetType;
  id: string;
}

/** Tab definition provided by each renderer component. */
export interface InspectorTab {
  id: string;
  label: string;
}

/** Emitted by InspectorService after an endorsement action completes. */
export interface InspectorAction {
  type: InspectorTargetType;
  id: string;
  action: string;
  timestamp: number;
}
