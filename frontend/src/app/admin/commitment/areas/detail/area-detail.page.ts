import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
} from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { map } from 'rxjs';
import { PlanService } from '../../../../core/services/plan.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { AreaDetail } from '../../../../core/models/admin.model';

/**
 * Area detail — a PARA area header (name / description / status) plus the
 * goals and projects filed under it, each row linking to its own detail.
 * Read-only; edit/delete live elsewhere. The list reads through `rxResource`
 * and is guarded by `hasValue()` so a failed load surfaces the error banner
 * instead of throwing.
 */
@Component({
  selector: 'app-area-detail-page',
  imports: [RouterLink],
  templateUrl: './area-detail.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class AreaDetailPageComponent {
  private readonly route = inject(ActivatedRoute);
  private readonly planService = inject(PlanService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly idFromRoute = toSignal(
    this.route.paramMap.pipe(map((p) => p.get('id') ?? '')),
    { initialValue: '' },
  );

  protected readonly resource = rxResource<AreaDetail, string>({
    params: () => this.idFromRoute(),
    stream: ({ params }) => this.planService.getAreaDetail(params),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). hasError() drives the
  // banner separately.
  private readonly detail = computed<AreaDetail | undefined>(() =>
    this.resource.hasValue() ? this.resource.value() : undefined,
  );
  protected readonly area = computed(() => this.detail()?.area);
  protected readonly goals = computed(() => this.detail()?.goals ?? []);
  protected readonly projects = computed(() => this.detail()?.projects ?? []);

  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading' && !this.detail(),
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  constructor() {
    this.topbar.set({ title: 'Area', crumbs: ['Commitment', 'Areas'] });

    effect(() => {
      const a = this.area();
      if (!a) return;
      this.topbar.set({
        title: `Area · ${a.name}`,
        crumbs: ['Commitment', 'Areas', a.name],
      });
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }
}
