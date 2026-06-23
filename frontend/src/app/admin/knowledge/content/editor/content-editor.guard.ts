import { isPlatformBrowser } from '@angular/common';
import { PLATFORM_ID, inject } from '@angular/core';
import type { CanDeactivateFn } from '@angular/router';
import type { ContentEditorPageComponent } from './content-editor.page';

/**
 * Blocks navigation away from the Content Editor while the form is
 * dirty. Falls through silently on the server (no `confirm` there).
 *
 * Functional guard (no class-based guards per angular-conventions.md). The
 * unsaved-changes prompt uses the native `window.confirm` by design — a
 * deliberate, dependency-free guard that does not pull in a dialog service.
 */
export const contentEditorCanDeactivate: CanDeactivateFn<
  ContentEditorPageComponent
> = (component) => {
  const platformId = inject(PLATFORM_ID);
  if (!isPlatformBrowser(platformId)) return true;
  if (!component.hasUnsavedChanges()) return true;
  return window.confirm('You have unsaved changes. Leave without saving?');
};
