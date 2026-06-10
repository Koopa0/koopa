import {
  ChangeDetectionStrategy,
  Component,
  input,
  output,
} from '@angular/core';
import { Hexagon, LucideAngularModule } from 'lucide-angular';

/** Discrete render states a dashboard widget can be in. */
export type WidgetState = 'loading' | 'error' | 'empty' | 'ok';

/**
 * Card shell for one Learning-dashboard widget. Owns the four-way state
 * machine (loading / error / empty / ok) so each widget degrades on its
 * own: a failing read renders an inline error with Retry while sibling
 * widgets stay live — one widget failing never blanks the page.
 */
@Component({
  selector: 'app-dashboard-widget',
  standalone: true,
  imports: [LucideAngularModule],
  templateUrl: './dashboard-widget.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'block min-w-0' },
})
export class DashboardWidgetComponent {
  readonly title = input.required<string>();
  /** Short mono meta on the head's right edge, shown while state is ok. */
  readonly meta = input('');
  readonly state = input.required<WidgetState>();
  readonly emptyTitle = input('Nothing here yet');
  readonly emptyBody = input("Come back once there's signal.");
  /** Suffix for data-testid hooks: widget-<id>[-loading|-error|-empty|-retry]. */
  readonly testId = input.required<string>();
  readonly retry = output<void>();

  protected readonly HexagonIcon = Hexagon;
}
