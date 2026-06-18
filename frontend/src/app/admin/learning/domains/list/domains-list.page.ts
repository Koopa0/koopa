import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { LearningService } from '../../../../core/services/learning.service';
import type { Domain } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';

/**
 * Domains List — Learning ontology roots. `GET /api/admin/learning/domains`
 * returns the flat domain list (slug + name); domains have no detail page so
 * rows are read-only. The endpoint may 404 or return empty until the backend
 * lands it, so empty and error states are first-class.
 */
@Component({
  selector: 'app-domains-list-page',
  imports: [DataTableComponent, RouterLink],
  templateUrl: './domains-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class DomainsListPageComponent {
  private readonly learningService = inject(LearningService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource<Domain[], void>({
    stream: () => this.learningService.getDomains(),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). hasError() drives
  // the error banner; without this guard a failed list read throws here.
  protected readonly rows = computed(() =>
    this.resource.hasValue() ? this.resource.value() : [],
  );
  protected readonly total = computed(() => this.rows().length);
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly isEmpty = computed(
    () => !this.isLoading() && this.rows().length === 0,
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  constructor() {
    this.topbar.set({ title: 'Domains', crumbs: ['Learning', 'Domains'] });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }
}
