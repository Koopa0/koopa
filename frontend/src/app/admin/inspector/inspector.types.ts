/**
 * Discriminated union of inspectable entities. Phase 0 supports goal +
 * project only; Phase 2 may extend to task, concept, content, directive,
 * report, plan, session, journal, insight.
 */
export type InspectorTarget =
  | { type: 'goal'; id: string }
  | { type: 'project'; id: string };

export type InspectorTargetType = InspectorTarget['type'];
