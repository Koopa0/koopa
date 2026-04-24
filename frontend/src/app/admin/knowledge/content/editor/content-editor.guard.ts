import { isPlatformBrowser } from '@angular/common';
import { PLATFORM_ID, inject } from '@angular/core';
import type { CanDeactivateFn } from '@angular/router';
import type { ContentEditorPageComponent } from './content-editor.page';

/**
 * Blocks navigation away from the Content Editor while the form is
 * dirty. Falls through silently on the server (no `confirm` there).
 *
 * Angular 21 — functional guard, no class-based guards per
 * angular-conventions.md.
 *
 * TODO(ux): replace `window.confirm` with the Catalyst Dialog component
 * once a shared DialogService lands. Native confirm is acceptable MVP
 * but visually breaks the dark-themed shell.
 */
export const contentEditorCanDeactivate: CanDeactivateFn<
  ContentEditorPageComponent
> = (component) => {
  const platformId = inject(PLATFORM_ID);
  if (!isPlatformBrowser(platformId)) return true;
  if (!component.hasUnsavedChanges()) return true;
  return window.confirm('You have unsaved changes. Leave without saving?');
};
