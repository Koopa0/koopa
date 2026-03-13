import type { CanDeactivateFn } from '@angular/router';

/** 元件實作此介面以啟用離開前未儲存變更提醒 */
export interface HasUnsavedChanges {
  hasUnsavedChanges(): boolean;
}

export const unsavedChangesGuard: CanDeactivateFn<HasUnsavedChanges> = (component) => {
  if (component.hasUnsavedChanges()) {
    return confirm('You have unsaved changes. Are you sure you want to leave?');
  }
  return true;
};
