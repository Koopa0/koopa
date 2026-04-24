import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  signal,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { rxResource } from '@angular/core/rxjs-interop';
import { map } from 'rxjs';
import { ContentService } from '../../core/services/content.service';
import { PlanService } from '../../core/services/plan.service';
import { InspectorService } from '../inspector/inspector.service';
import {
  ENTITY_TYPE_META,
  type EntityTypeMeta,
  type InspectorTargetType,
} from '../../core/models/workbench.model';

/** Governance posture — derived from entity lifecycle state. */
type GovernancePosture = 'candidate' | 'working' | 'canonical';

interface AtlasItem {
  type: InspectorTargetType;
  id: string;
  title: string;
  area: string;
  status: string;
  posture: GovernancePosture;
  searchHaystack: string;
}

/** Derive governance posture from entity type + status. */
function derivePosture(
  type: InspectorTargetType,
  status: string,
): GovernancePosture {
  switch (type) {
    case 'content':
      if (status === 'draft') return 'candidate';
      if (status === 'review') return 'working';
      return 'canonical';
    case 'goal':
      if (status === 'not_started') return 'candidate';
      if (status === 'in_progress' || status === 'on_hold') return 'working';
      return 'canonical';
    case 'project':
      if (status === 'planned') return 'candidate';
      if (status === 'in_progress' || status === 'on_hold') return 'working';
      return 'canonical';
    default:
      return 'canonical';
  }
}

/**
 * Atlas — faceted cross-entity search.
 *
 * Supports goal, project, and content entity types.
 * Governance posture facet derives from lifecycle state.
 */
@Component({
  selector: 'app-atlas-page',
  standalone: true,
  imports: [],
  templateUrl: './atlas-page.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AtlasPageComponent {
  private readonly planService = inject(PlanService);
  private readonly contentService = inject(ContentService);
  private readonly route = inject(ActivatedRoute);
  protected readonly inspector = inject(InspectorService);

  protected readonly query = signal('');
  protected readonly enabledTypes = signal<Set<InspectorTargetType>>(
    new Set(['goal', 'project', 'content']),
  );
  protected readonly enabledPostures = signal<Set<GovernancePosture>>(
    new Set(),
  );

  constructor() {
    // URL → signal sync. NowPage cells navigate here with `?type=X&q=Y` for
    // entity types whose Inspector is deferred, agent).
    // We pre-fill the search; type filter is applied only when the type is
    // actually loaded as a facet (otherwise we leave default types enabled
    // so the user sees something rather than an empty result).
    this.route.queryParamMap.pipe(takeUntilDestroyed()).subscribe((params) => {
      const q = params.get('q');
      if (q) this.query.set(q);
      const type = params.get('type') as InspectorTargetType | null;
      if (type && this.typeFacets.some((f) => f.type === type)) {
        this.enabledTypes.set(new Set([type]));
      }
    });
  }

  /** Entity metadata lookup. See inspector-panel for why this is a method. */
  protected meta(type: InspectorTargetType): EntityTypeMeta {
    return ENTITY_TYPE_META[type];
  }

  /** All available type facets. */
  protected readonly typeFacets: {
    type: InspectorTargetType;
    label: string;
  }[] = [
    { type: 'content', label: 'Content' },
    { type: 'goal', label: 'Goal' },
    { type: 'project', label: 'Project' },
    // Add here as APIs are built:
    // { type: 'hypothesis', label: 'Hypothesis' },
    // { type: 'task', label: 'Task' },
  ];

  protected readonly postureFacets: {
    posture: GovernancePosture;
    label: string;
  }[] = [
    { posture: 'candidate', label: 'Candidate' },
    { posture: 'working', label: 'Working' },
    { posture: 'canonical', label: 'Canonical' },
  ];

  // === Data loading ===

  private readonly goalsResource = rxResource<AtlasItem[], void>({
    stream: () =>
      this.planService.getGoalsOverview().pipe(
        map((r) =>
          r.goals.map(
            (g): AtlasItem => ({
              type: 'goal',
              id: g.id,
              title: g.title,
              area: g.area_name,
              status: g.status,
              posture: derivePosture('goal', g.status),
              searchHaystack:
                `${g.title} ${g.area_name} ${g.status} ${g.quarter ?? ''}`
                  .trim()
                  .toLowerCase(),
            }),
          ),
        ),
      ),
  });

  private readonly projectsResource = rxResource<AtlasItem[], void>({
    stream: () =>
      this.planService.getProjectsOverview().pipe(
        map((r) =>
          r.projects.map(
            (p): AtlasItem => ({
              type: 'project',
              id: p.id,
              title: p.title,
              area: p.area,
              status: p.status,
              posture: derivePosture('project', p.status),
              searchHaystack: `${p.title} ${p.area} ${p.status}`.toLowerCase(),
            }),
          ),
        ),
      ),
  });

  private readonly contentResource = rxResource<AtlasItem[], void>({
    stream: () =>
      this.contentService.adminList().pipe(
        map((r) =>
          r.data.map(
            (c): AtlasItem => ({
              type: 'content',
              id: c.id,
              title: c.title,
              area: c.type,
              status: c.status,
              posture: derivePosture('content', c.status),
              searchHaystack:
                `${c.title} ${c.type} ${c.status} ${c.slug}`.toLowerCase(),
            }),
          ),
        ),
      ),
  });

  protected readonly isLoading = computed(
    () =>
      this.goalsResource.status() === 'loading' ||
      this.projectsResource.status() === 'loading' ||
      this.contentResource.status() === 'loading',
  );

  /** All items merged. */
  private readonly allItems = computed<AtlasItem[]>(() => {
    const goals = this.goalsResource.value() ?? [];
    const projects = this.projectsResource.value() ?? [];
    const content = this.contentResource.value() ?? [];
    return [...goals, ...projects, ...content];
  });

  /** Filtered by facets + search. */
  protected readonly filteredItems = computed<AtlasItem[]>(() => {
    const q = this.query().trim().toLowerCase();
    const types = this.enabledTypes();
    const postures = this.enabledPostures();
    const hasPostureFilter = postures.size > 0;

    return this.allItems().filter((item) => {
      if (!types.has(item.type)) return false;
      if (hasPostureFilter && !postures.has(item.posture)) return false;
      if (q && !item.searchHaystack.includes(q)) return false;
      return true;
    });
  });

  protected readonly counts = computed(() => {
    const all = this.filteredItems();
    const byType: Partial<Record<InspectorTargetType, number>> = {};
    for (const item of all) {
      byType[item.type] = (byType[item.type] ?? 0) + 1;
    }
    return { total: all.length, byType };
  });

  // === Actions ===

  protected onSearchInput(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
  }

  protected toggleType(type: InspectorTargetType): void {
    this.enabledTypes.update((set) => {
      const next = new Set(set);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  }

  protected togglePosture(posture: GovernancePosture): void {
    this.enabledPostures.update((set) => {
      const next = new Set(set);
      if (next.has(posture)) {
        next.delete(posture);
      } else {
        next.add(posture);
      }
      return next;
    });
  }

  protected isTypeEnabled(type: InspectorTargetType): boolean {
    return this.enabledTypes().has(type);
  }

  protected isPostureEnabled(posture: GovernancePosture): boolean {
    return this.enabledPostures().has(posture);
  }

  protected openInspector(item: AtlasItem): void {
    this.inspector.open({ type: item.type, id: item.id });
  }

  protected typeCount(type: InspectorTargetType): number {
    return this.counts().byType[type] ?? 0;
  }
}
