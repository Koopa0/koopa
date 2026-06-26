import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { BreakpointObserver } from '@angular/cdk/layout';
import { of } from 'rxjs';
import { AdminLayoutComponent } from './admin-layout';
import { AdminTopbarService } from './admin-topbar.service';

/** Reports a mobile viewport so isMobile() is true. */
class MobileBreakpointObserver {
  observe() {
    return of({ matches: true, breakpoints: {} });
  }
}

describe('AdminLayoutComponent', () => {
  let component: AdminLayoutComponent;
  let fixture: ComponentFixture<AdminLayoutComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AdminLayoutComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(AdminLayoutComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render the drawer backdrop only when the drawer is open', () => {
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(
      el.querySelector('[data-testid="admin-drawer-backdrop"]'),
    ).toBeNull();

    TestBed.inject(AdminTopbarService).toggleDrawer();
    fixture.detectChanges();

    expect(
      el.querySelector('[data-testid="admin-drawer-backdrop"]'),
    ).not.toBeNull();
  });

  it('should close the drawer when the backdrop is clicked', () => {
    fixture.detectChanges();

    const topbar = TestBed.inject(AdminTopbarService);
    topbar.toggleDrawer();
    fixture.detectChanges();

    const backdrop = fixture.nativeElement.querySelector(
      '[data-testid="admin-drawer-backdrop"]',
    ) as HTMLElement;
    backdrop.click();
    fixture.detectChanges();

    expect(topbar.drawerOpen()).toBe(false);
  });

  it('should never mark the sidebar inert on desktop', () => {
    fixture.detectChanges();

    const aside = fixture.nativeElement.querySelector(
      '#admin-drawer',
    ) as HTMLElement;
    // On desktop the rail is static and must stay interactive whether or not
    // the drawer signal is set.
    expect(aside.hasAttribute('inert')).toBe(false);
  });
});

describe('AdminLayoutComponent (mobile viewport)', () => {
  let fixture: ComponentFixture<AdminLayoutComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AdminLayoutComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: BreakpointObserver, useClass: MobileBreakpointObserver },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(AdminLayoutComponent);
  });

  it('should mark the closed drawer inert on mobile and clear it when open', () => {
    fixture.detectChanges();

    const aside = fixture.nativeElement.querySelector(
      '#admin-drawer',
    ) as HTMLElement;
    // Closed + mobile: off-canvas, so removed from the tab order and a11y tree.
    expect(aside.hasAttribute('inert')).toBe(true);

    TestBed.inject(AdminTopbarService).toggleDrawer();
    fixture.detectChanges();
    // Open: interactive again so keyboard/screen-reader users can use the nav.
    expect(aside.hasAttribute('inert')).toBe(false);
  });
});
