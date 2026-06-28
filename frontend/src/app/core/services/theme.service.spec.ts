import { TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { ThemeService } from './theme.service';

/**
 * The Angular unit-test builder runs in a Node-flavoured environment
 * where `localStorage` is not always available. Install an in-memory
 * Map-backed Storage stub so persistence assertions work everywhere.
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

describe('ThemeService', () => {
  let storage: Map<string, string>;

  beforeAll(() => {
    storage = installLocalStorageStub();
  });

  afterAll(() => {
    vi.unstubAllGlobals();
  });

  describe('in browser', () => {
    let service: ThemeService;

    beforeEach(() => {
      storage.clear();
      document.documentElement.classList.remove('public-dark');
      TestBed.configureTestingModule({
        providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
      });
      service = TestBed.inject(ThemeService);
    });

    afterEach(() => {
      storage.clear();
      document.documentElement.classList.remove('public-dark');
    });

    it('should be created', () => {
      expect(service).toBeTruthy();
    });

    it('should default to paper (light) when no choice is persisted', () => {
      expect(service.theme()).toBe('light');
      expect(service.isDarkMode()).toBe(false);
    });

    it('should leave public-dark off on the paper default', () => {
      expect(document.documentElement.classList.contains('public-dark')).toBe(
        false,
      );
    });

    it('should add the public-dark class when setTheme(dark) is called', () => {
      service.setTheme('dark');
      expect(service.theme()).toBe('dark');
      expect(service.isDarkMode()).toBe(true);
      expect(document.documentElement.classList.contains('public-dark')).toBe(
        true,
      );
    });

    it('should persist the choice to localStorage when toggled', () => {
      service.toggleTheme();
      expect(service.theme()).toBe('dark');
      expect(storage.get('koopa-public-theme')).toBe('dark');

      service.toggleTheme();
      expect(service.theme()).toBe('light');
      expect(storage.get('koopa-public-theme')).toBe('light');
      expect(document.documentElement.classList.contains('public-dark')).toBe(
        false,
      );
    });

    it('should update the theme-color meta when the theme changes', () => {
      service.setTheme('dark');
      const meta = document.querySelector('meta[name="theme-color"]');
      expect(meta?.getAttribute('content')).toBe('#14130f');

      service.setTheme('light');
      expect(meta?.getAttribute('content')).toBe('#edeae2');
    });
  });

  describe('with a persisted dark choice', () => {
    it('should restore the dark twin from localStorage', () => {
      storage.set('koopa-public-theme', 'dark');
      document.documentElement.classList.remove('public-dark');
      TestBed.configureTestingModule({
        providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
      });
      const service = TestBed.inject(ThemeService);

      expect(service.theme()).toBe('dark');
      expect(document.documentElement.classList.contains('public-dark')).toBe(
        true,
      );

      storage.clear();
      document.documentElement.classList.remove('public-dark');
    });
  });

  describe('on server', () => {
    let service: ThemeService;

    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [{ provide: PLATFORM_ID, useValue: 'server' }],
      });
      service = TestBed.inject(ThemeService);
    });

    it('should be created on server', () => {
      expect(service).toBeTruthy();
    });

    it('should default to paper (light) on server', () => {
      expect(service.isDarkMode()).toBe(false);
    });

    it('should not throw when setTheme is called on server', () => {
      expect(() => service.setTheme('dark')).not.toThrow();
      expect(service.theme()).toBe('dark');
    });
  });
});
