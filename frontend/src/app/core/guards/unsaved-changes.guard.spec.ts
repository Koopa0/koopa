import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  unsavedChangesGuard,
  type HasUnsavedChanges,
} from './unsaved-changes.guard';
import type {
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
} from '@angular/router';

describe('unsavedChangesGuard', () => {
  let mockComponent: HasUnsavedChanges;
  let mockRoute: ActivatedRouteSnapshot;
  let mockCurrentState: RouterStateSnapshot;
  let mockNextState: RouterStateSnapshot;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideRouter([])],
    });

    mockComponent = { hasUnsavedChanges: vi.fn() };
    mockRoute = {} as ActivatedRouteSnapshot;
    mockCurrentState = {} as RouterStateSnapshot;
    mockNextState = {} as RouterStateSnapshot;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should allow navigation when no unsaved changes', () => {
    vi.mocked(mockComponent.hasUnsavedChanges).mockReturnValue(false);

    const result = TestBed.runInInjectionContext(() =>
      unsavedChangesGuard(
        mockComponent,
        mockRoute,
        mockCurrentState,
        mockNextState,
      ),
    );

    expect(result).toBe(true);
    expect(mockComponent.hasUnsavedChanges).toHaveBeenCalled();
  });

  it('should prompt confirmation when unsaved changes exist', () => {
    vi.mocked(mockComponent.hasUnsavedChanges).mockReturnValue(true);
    vi.spyOn(globalThis, 'confirm').mockReturnValue(true);

    const result = TestBed.runInInjectionContext(() =>
      unsavedChangesGuard(
        mockComponent,
        mockRoute,
        mockCurrentState,
        mockNextState,
      ),
    );

    expect(result).toBe(true);
    expect(globalThis.confirm).toHaveBeenCalledWith(
      'You have unsaved changes. Are you sure you want to leave?',
    );
  });

  it('should block navigation when user cancels', () => {
    vi.mocked(mockComponent.hasUnsavedChanges).mockReturnValue(true);
    vi.spyOn(globalThis, 'confirm').mockReturnValue(false);

    const result = TestBed.runInInjectionContext(() =>
      unsavedChangesGuard(
        mockComponent,
        mockRoute,
        mockCurrentState,
        mockNextState,
      ),
    );

    expect(result).toBe(false);
    expect(globalThis.confirm).toHaveBeenCalled();
  });
});
