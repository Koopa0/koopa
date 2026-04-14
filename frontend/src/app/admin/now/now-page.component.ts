import { ChangeDetectionStrategy, Component } from '@angular/core';
import { OverviewComponent } from '../overview/overview';

/**
 * NOW mode entry point. Phase 1 placeholder: delegates to OverviewComponent
 * so the route is functional during the shell migration. Day 8 replaces
 * this with the dedicated 3-column workspace (Attention Queue | Today
 * Stream | Ambient) defined in the admin-v2 plan.
 */
@Component({
  selector: 'app-now-page',
  standalone: true,
  imports: [OverviewComponent],
  template: '<app-overview />',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NowPageComponent {}
