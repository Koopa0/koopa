import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { AdminLayoutComponent } from './admin-layout';
import { AdminTopbarService } from './admin-topbar.service';

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
});
