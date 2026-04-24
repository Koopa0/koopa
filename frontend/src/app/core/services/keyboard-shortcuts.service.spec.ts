import { TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { Router } from '@angular/router';
import { KeyboardShortcutsService } from './keyboard-shortcuts.service';

const A11Y_STORAGE_KEY = 'koopa:a11y-mode';

/**
 * The Angular unit-test builder runs in a Node-flavoured environment
 * where `localStorage.removeItem` is not always a function. Install an
 * in-memory Map-backed Storage stub so the service's own try/catch
 * guards still exercise the happy path during tests.
 */
function installLocalStorageStub(): Map<string, string> {
  const data = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (k: string) => data.get(k) ?? null,
    key: (i: number) => Array.from(data.keys())[i] ?? null,
    removeItem: (k: string) => {
      data.delete(k);
    },
    setItem: (k: string, v: string) => {
      data.set(k, v);
    },
  } satisfies Storage);
  return data;
}

describe('KeyboardShortcutsService', () => {
  let routerStub: { navigate: ReturnType<typeof vi.fn>; url: string };
  let storage: Map<string, string>;

  beforeAll(() => {
    storage = installLocalStorageStub();
  });

  afterAll(() => {
    vi.unstubAllGlobals();
  });

  function setupBrowser(currentUrl = '/'): KeyboardShortcutsService {
    routerStub = { navigate: vi.fn(), url: currentUrl };

    TestBed.configureTestingModule({
      providers: [
        { provide: PLATFORM_ID, useValue: 'browser' },
        { provide: Router, useValue: routerStub },
      ],
    });
    const service = TestBed.inject(KeyboardShortcutsService);
    service.init();
    return service;
  }

  function setupServer(): KeyboardShortcutsService {
    routerStub = { navigate: vi.fn(), url: '/' };

    TestBed.configureTestingModule({
      providers: [
        { provide: PLATFORM_ID, useValue: 'server' },
        { provide: Router, useValue: routerStub },
      ],
    });
    return TestBed.inject(KeyboardShortcutsService);
  }

  function dispatchKey(
    key: string,
    opts: { shift?: boolean; meta?: boolean; ctrl?: boolean } = {},
  ): void {
    const event = new KeyboardEvent('keydown', {
      key,
      shiftKey: opts.shift ?? false,
      metaKey: opts.meta ?? false,
      ctrlKey: opts.ctrl ?? false,
      bubbles: true,
      cancelable: true,
    });
    document.dispatchEvent(event);
  }

  beforeEach(() => {
    storage.clear();
  });

  afterEach(() => {
    storage.clear();
  });

  describe('lifecycle', () => {
    it('should be created in browser', () => {
      const service = setupBrowser();
      expect(service).toBeTruthy();
    });

    it('should be created on server without throwing', () => {
      const service = setupServer();
      expect(service).toBeTruthy();
      expect(() => service.init()).not.toThrow();
    });

    it('should ignore subsequent init calls', () => {
      const service = setupBrowser();
      expect(() => service.init()).not.toThrow();
    });
  });

  describe('admin G-prefix navigation', () => {
    it('should navigate on `G H` chord from inside admin', () => {
      setupBrowser('/admin/commitment/today');
      dispatchKey('g');
      dispatchKey('h');
      expect(routerStub.navigate).toHaveBeenCalledWith([
        '/admin/commitment/today',
      ]);
    });

    it('should navigate on `G R` chord to review queue', () => {
      setupBrowser('/admin/commitment/today');
      dispatchKey('g');
      dispatchKey('r');
      expect(routerStub.navigate).toHaveBeenCalledWith([
        '/admin/knowledge/review-queue',
      ]);
    });

    it('should NOT navigate when the G-prefix target is unknown', () => {
      setupBrowser('/admin/commitment/today');
      dispatchKey('g');
      dispatchKey('q');
      expect(routerStub.navigate).not.toHaveBeenCalled();
    });

    it('should NOT fire G-prefix outside /admin', () => {
      setupBrowser('/articles');
      dispatchKey('g');
      dispatchKey('t');
      expect(routerStub.navigate).not.toHaveBeenCalled();
    });
  });

  describe('global shortcuts', () => {
    it('should navigate to /admin on Shift+A', () => {
      setupBrowser('/articles');
      dispatchKey('A', { shift: true });
      expect(routerStub.navigate).toHaveBeenCalledWith(['/admin']);
    });

    it('should ignore Shift+A in form controls', () => {
      setupBrowser('/articles');
      const input = document.createElement('input');
      document.body.appendChild(input);
      input.focus();
      const event = new KeyboardEvent('keydown', {
        key: 'A',
        shiftKey: true,
        bubbles: true,
        cancelable: true,
      });
      input.dispatchEvent(event);
      document.body.removeChild(input);
      expect(routerStub.navigate).not.toHaveBeenCalled();
    });
  });

  describe('a11y mode', () => {
    it('should default to false when localStorage is empty', () => {
      const service = setupBrowser();
      expect(service.a11yMode()).toBe(false);
    });

    it('should read persisted true value at construction', () => {
      localStorage.setItem(A11Y_STORAGE_KEY, 'true');
      const service = setupBrowser();
      expect(service.a11yMode()).toBe(true);
    });

    it('should toggle a11y mode and persist to localStorage', () => {
      const service = setupBrowser();
      service.toggleA11yMode();
      expect(service.a11yMode()).toBe(true);
      expect(localStorage.getItem(A11Y_STORAGE_KEY)).toBe('true');

      service.toggleA11yMode();
      expect(service.a11yMode()).toBe(false);
      expect(localStorage.getItem(A11Y_STORAGE_KEY)).toBe('false');
    });

    it('should disable G-prefix chord when a11y mode is on', () => {
      const service = setupBrowser('/admin/commitment/today');
      service.toggleA11yMode();

      dispatchKey('g');
      dispatchKey('t');
      expect(routerStub.navigate).not.toHaveBeenCalled();
    });

    it('should still allow Shift+A when a11y mode is on (modifier bypass)', () => {
      const service = setupBrowser('/articles');
      service.toggleA11yMode();

      dispatchKey('A', { shift: true });
      expect(routerStub.navigate).toHaveBeenCalledWith(['/admin']);
    });
  });
});
