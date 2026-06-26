import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { AdminTopbarComponent } from './admin-topbar.component';
import { AdminTopbarService } from './admin-topbar.service';

describe('AdminTopbarComponent', () => {
  let fixture: ComponentFixture<AdminTopbarComponent>;
  let topbar: AdminTopbarService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AdminTopbarComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();

    topbar = TestBed.inject(AdminTopbarService);
    fixture = TestBed.createComponent(AdminTopbarComponent);
  });

  afterEach(() => {
    topbar.reset();
  });

  it('should render the title and crumbs when the service publishes context', () => {
    topbar.set({ title: 'Content', crumbs: ['knowledge', 'content'] });
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(
      el.querySelector('[data-testid="topbar-title"]')?.textContent,
    ).toContain('Content');
    expect(
      el.querySelector('[data-testid="topbar-crumbs"]')?.textContent,
    ).toContain('knowledge');
  });

  it('should hide the title and crumbs when the context is empty', () => {
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="topbar-title"]')).toBeNull();
    expect(el.querySelector('[data-testid="topbar-crumbs"]')).toBeNull();
  });

  it('should run the action handler when an action chip is clicked', () => {
    const run = vi.fn();
    topbar.set({
      title: 'Content',
      actions: [{ id: 'save', label: 'Save', kind: 'primary', run }],
    });
    fixture.detectChanges();

    const button = fixture.nativeElement.querySelector(
      '[data-testid="topbar-action-save"]',
    ) as HTMLButtonElement;
    button.click();

    expect(run).toHaveBeenCalledTimes(1);
  });

  it('should not run a disabled action when clicked', () => {
    const run = vi.fn();
    topbar.set({
      title: 'Content',
      actions: [{ id: 'save', label: 'Save', disabled: true, run }],
    });
    fixture.detectChanges();

    const button = fixture.nativeElement.querySelector(
      '[data-testid="topbar-action-save"]',
    ) as HTMLButtonElement;
    button.click();

    expect(run).not.toHaveBeenCalled();
  });

  it('should open the nav drawer when the hamburger toggle is clicked', () => {
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    const toggle = el.querySelector(
      '[data-testid="admin-drawer-toggle"]',
    ) as HTMLButtonElement;
    expect(topbar.drawerOpen()).toBe(false);
    expect(toggle.getAttribute('aria-expanded')).toBe('false');

    toggle.click();
    fixture.detectChanges();

    expect(topbar.drawerOpen()).toBe(true);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
  });

  it('should surface overflow actions inside the … menu when toggled', () => {
    const run = vi.fn();
    topbar.set({
      title: 'Content',
      overflowActions: [{ id: 'archive', label: 'Archive', run }],
    });
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="topbar-overflow-menu"]')).toBeNull();

    (
      el.querySelector(
        '[data-testid="topbar-overflow-toggle"]',
      ) as HTMLButtonElement
    ).click();
    fixture.detectChanges();

    const item = el.querySelector(
      '[data-testid="topbar-overflow-action-archive"]',
    ) as HTMLButtonElement;
    expect(item).not.toBeNull();

    item.click();
    expect(run).toHaveBeenCalledTimes(1);
  });
});
