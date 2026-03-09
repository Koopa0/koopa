import { Component, ChangeDetectionStrategy } from '@angular/core';

/**
 * ThemeToggle — Disabled.
 * The site currently uses dark mode only; theme switching is no longer available.
 * This component is retained to avoid breaking existing references.
 */
@Component({
  selector: 'app-theme-toggle',
  standalone: true,
  template: ``,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ThemeToggleComponent {}
