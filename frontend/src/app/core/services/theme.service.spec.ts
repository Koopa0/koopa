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
      TestBed.configureTestingModule({
        providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
      });
      service = TestBed.inject(ThemeService);
    });

    afterEach(() => {
      storage.clear();
      document.documentElement.setAttribute('data-theme', 'dark');
    });

    it('should be created', () => {
      expect(service).toBeTruthy();
    });

    it('should default to dark mode when no choice is persisted', () => {
      expect(service.theme()).toBe('dark');
      expect(service.isDarkMode()).toBe(true);
    });

    it('should set data-theme attribute to dark by default', () => {
      const theme = document.documentElement.getAttribute('data-theme');
      expect(theme).toBe('dark');
    });

    it('should switch data-theme to light when setTheme is called', () => {
      service.setTheme('light');
      expect(service.theme()).toBe('light');
      expect(service.isDarkMode()).toBe(false);
      expect(document.documentElement.getAttribute('data-theme')).toBe(
        'light',
      );
    });

    it('should persist the choice to localStorage when toggled', () => {
      service.toggleTheme();
      expect(service.theme()).toBe('light');
      expect(storage.get('koopa-theme')).toBe('light');

      service.toggleTheme();
      expect(service.theme()).toBe('dark');
      expect(storage.get('koopa-theme')).toBe('dark');
    });

    it('should update the theme-color meta when the theme changes', () => {
      service.setTheme('light');
      const meta = document.querySelector('meta[name="theme-color"]');
      expect(meta?.getAttribute('content')).toBe('#fbfaf8');

      service.setTheme('dark');
      expect(meta?.getAttribute('content')).toBe('#141417');
    });
  });

  describe('with a persisted light choice', () => {
    it('should restore light mode from localStorage', () => {
      storage.set('koopa-theme', 'light');
      TestBed.configureTestingModule({
        providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
      });
      const service = TestBed.inject(ThemeService);

      expect(service.theme()).toBe('light');
      expect(document.documentElement.getAttribute('data-theme')).toBe(
        'light',
      );

      storage.clear();
      document.documentElement.setAttribute('data-theme', 'dark');
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

    it('should default to dark mode on server', () => {
      expect(service.isDarkMode()).toBe(true);
    });

    it('should not throw when setTheme is called on server', () => {
      expect(() => service.setTheme('light')).not.toThrow();
      expect(service.theme()).toBe('light');
    });
  });
});
