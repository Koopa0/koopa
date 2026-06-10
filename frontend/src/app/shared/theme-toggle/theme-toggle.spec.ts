import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { ThemeToggleComponent } from './theme-toggle';
import { ThemeService } from '../../core/services/theme.service';

/**
 * The Angular unit-test builder runs in a Node-flavoured environment
 * where `localStorage` is not always available. Install an in-memory
 * Map-backed Storage stub so ThemeService persistence works in tests.
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

describe('ThemeToggleComponent', () => {
  let component: ThemeToggleComponent;
  let fixture: ComponentFixture<ThemeToggleComponent>;
  let themeService: ThemeService;
  let storage: Map<string, string>;

  beforeAll(() => {
    storage = installLocalStorageStub();
  });

  afterAll(() => {
    vi.unstubAllGlobals();
  });

  beforeEach(async () => {
    storage.clear();
    await TestBed.configureTestingModule({
      imports: [ThemeToggleComponent],
      providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
    }).compileComponents();

    themeService = TestBed.inject(ThemeService);
    fixture = TestBed.createComponent(ThemeToggleComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => {
    storage.clear();
    document.documentElement.setAttribute('data-theme', 'dark');
  });

  function toggleButton(): HTMLButtonElement {
    return fixture.nativeElement.querySelector(
      '[data-testid="theme-toggle"]',
    ) as HTMLButtonElement;
  }

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render an enabled toggle button', () => {
    const button = toggleButton();
    expect(button).toBeTruthy();
    expect(button.disabled).toBe(false);
  });

  it('should offer the light theme while dark is active', () => {
    expect(toggleButton().getAttribute('aria-label')).toBe(
      'Switch to light theme',
    );
  });

  it('should toggle the theme when clicked', () => {
    toggleButton().click();
    fixture.detectChanges();

    expect(themeService.theme()).toBe('light');
    expect(toggleButton().getAttribute('aria-label')).toBe(
      'Switch to dark theme',
    );

    toggleButton().click();
    fixture.detectChanges();

    expect(themeService.theme()).toBe('dark');
  });
});
