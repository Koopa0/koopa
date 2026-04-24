import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { InspectorService } from './inspector.service';

describe('InspectorService', () => {
  let service: InspectorService;
  let router: Router;
  let navigateSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideRouter([])],
    });
    service = TestBed.inject(InspectorService);
    router = TestBed.inject(Router);
    navigateSpy = vi.spyOn(router, 'navigate').mockResolvedValue(true);
  });

  it('should be created with no target', () => {
    expect(service).toBeTruthy();
    expect(service.target()).toBeNull();
    expect(service.isOpen()).toBe(false);
  });

  it('should update URL when opening a goal target', () => {
    service.open({ type: 'goal', id: 'abc-123' });

    expect(navigateSpy).toHaveBeenCalledWith([], {
      queryParams: { inspect: 'goal:abc-123' },
      queryParamsHandling: 'merge',
    });
  });

  it('should update URL when opening a project target', () => {
    service.open({ type: 'project', id: 'proj-9' });

    expect(navigateSpy).toHaveBeenCalledWith([], {
      queryParams: { inspect: 'project:proj-9' },
      queryParamsHandling: 'merge',
    });
  });

  it('should clear URL param on close', () => {
    service.close();

    expect(navigateSpy).toHaveBeenCalledWith([], {
      queryParams: { inspect: null },
      queryParamsHandling: 'merge',
    });
  });

  it('should set target from valid goal URL value', () => {
    service.syncFromUrl('goal:abc-123');

    expect(service.target()).toEqual({ type: 'goal', id: 'abc-123' });
    expect(service.isOpen()).toBe(true);
  });

  it('should set target from valid project URL value', () => {
    service.syncFromUrl('project:proj-9');

    expect(service.target()).toEqual({ type: 'project', id: 'proj-9' });
    expect(service.isOpen()).toBe(true);
  });

  it('should clear target when URL value is null', () => {
    service.syncFromUrl('goal:abc');
    expect(service.isOpen()).toBe(true);

    service.syncFromUrl(null);
    expect(service.target()).toBeNull();
    expect(service.isOpen()).toBe(false);
  });

  it('should clear target when URL value is undefined', () => {
    service.syncFromUrl('goal:abc');
    service.syncFromUrl(undefined);
    expect(service.target()).toBeNull();
  });

  it('should clear target when URL value is empty string', () => {
    service.syncFromUrl('goal:abc');
    service.syncFromUrl('');
    expect(service.target()).toBeNull();
  });

  it('should reject malformed URL value with no colon', () => {
    service.syncFromUrl('malformed');
    expect(service.target()).toBeNull();
  });

  it('should reject URL value with empty id', () => {
    service.syncFromUrl('goal:');
    expect(service.target()).toBeNull();
  });

  it('should reject unknown entity type', () => {
    service.syncFromUrl('widget:abc-123');
    expect(service.target()).toBeNull();
  });

  it('should support ids containing colons', () => {
    // Extensible: if any future id contains a colon, the parser should
    // split on the first colon only.
    service.syncFromUrl('goal:uuid:with:colons');
    expect(service.target()).toEqual({
      type: 'goal',
      id: 'uuid:with:colons',
    });
  });
});
