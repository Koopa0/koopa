import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import {
  ActivatedRoute,
  Router,
  RouterLink,
  RouterLinkActive,
  RouterOutlet,
} from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  Accessibility,
  Home,
  Library,
  LogOut,
  LucideAngularModule,
} from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { KeyboardShortcutsService } from '../../core/services/keyboard-shortcuts.service';
import { ToastComponent } from '../../shared/toast/toast.component';
import { InspectorService } from '../inspector/inspector.service';
import { InspectorPanelComponent } from '../inspector/inspector-panel.component';
import { StatusRibbonComponent } from './status-ribbon.component';

interface ModeItem {
  label: string;
  route: string;
  icon: typeof Home;
  shortcut: string;
}

/**
 * Admin shell. Top status ribbon, left rail with two mode icons (NOW,
 * ATLAS), main router outlet, and the cross-cutting inspector panel
 * mounted as a sibling so it survives mode switches. The legacy 6-group
 * sidebar lived here before admin-v2 — that taxonomy was entity-oriented;
 * the new shell is intent-oriented (NOW = what needs me, ATLAS = explore).
 */
@Component({
  selector: 'app-admin-layout',
  standalone: true,
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    LucideAngularModule,
    ToastComponent,
    InspectorPanelComponent,
    StatusRibbonComponent,
  ],
  templateUrl: './admin-layout.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex h-[calc(100dvh-57px)] flex-col' },
})
export class AdminLayoutComponent {
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly authService = inject(AuthService);
  private readonly inspector = inject(InspectorService);
  private readonly keyboardShortcuts = inject(KeyboardShortcutsService);

  protected readonly modes: ModeItem[] = [
    { label: 'NOW', route: '/admin/now', icon: Home, shortcut: '1' },
    { label: 'ATLAS', route: '/admin/atlas', icon: Library, shortcut: '2' },
  ];

  protected readonly a11yMode = this.keyboardShortcuts.a11yMode;

  protected readonly LogOutIcon = LogOut;
  protected readonly AccessibilityIcon = Accessibility;

  constructor() {
    // URL → InspectorService sync. Reading the `?inspect=` query param at
    // the shell level keeps share-link entry points working without each
    // page wiring its own watcher.
    this.route.queryParamMap.pipe(takeUntilDestroyed()).subscribe((params) => {
      this.inspector.syncFromUrl(params.get('inspect'));
    });
  }

  protected logout(): void {
    this.authService.logout();
    this.router.navigate(['/']);
  }

  protected toggleA11yMode(): void {
    this.keyboardShortcuts.toggleA11yMode();
  }
}
