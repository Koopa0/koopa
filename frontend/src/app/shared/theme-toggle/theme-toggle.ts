import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { LucideAngularModule, Sun, Moon } from 'lucide-angular';
import { ThemeService } from '../../core/services/theme.service';

/**
 * ThemeToggle — flips between the dark (default) and light (warm-paper)
 * themes via ThemeService. Shows a sun while dark and a moon while light,
 * matching the action the click performs.
 */
@Component({
  selector: 'app-theme-toggle',
  imports: [LucideAngularModule],
  template: `
    <button
      type="button"
      (click)="themeService.toggleTheme()"
      class="flex size-9 items-center justify-center rounded-full border border-border-faint text-fg-subtle transition-colors hover:border-border hover:bg-overlay hover:text-fg"
      [attr.aria-label]="
        themeService.isDarkMode()
          ? 'Switch to light theme'
          : 'Switch to dark theme'
      "
      data-testid="theme-toggle"
    >
      @if (themeService.isDarkMode()) {
        <lucide-icon [img]="SunIcon" [size]="16" [strokeWidth]="1.6" />
      } @else {
        <lucide-icon [img]="MoonIcon" [size]="16" [strokeWidth]="1.6" />
      }
    </button>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ThemeToggleComponent {
  protected readonly themeService = inject(ThemeService);

  protected readonly SunIcon = Sun;
  protected readonly MoonIcon = Moon;
}
