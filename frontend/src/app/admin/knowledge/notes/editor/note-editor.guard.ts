import { isPlatformBrowser } from '@angular/common';
import { PLATFORM_ID, inject } from '@angular/core';
import type { CanDeactivateFn } from '@angular/router';
import type { NoteEditorPageComponent } from './note-editor.page';

/**
 * Blocks navigation away from the Note Editor while the form is dirty.
 * Mirrors content-editor.guard.ts — same shape, different component
 * generic.
 *
 * TODO(ux): replace `window.confirm` with the Catalyst Dialog once a
 * shared DialogService lands.
 */
export const noteEditorCanDeactivate: CanDeactivateFn<
  NoteEditorPageComponent
> = (component) => {
  const platformId = inject(PLATFORM_ID);
  if (!isPlatformBrowser(platformId)) return true;
  if (!component.hasUnsavedChanges()) return true;
  return window.confirm('You have unsaved changes. Leave without saving?');
};
