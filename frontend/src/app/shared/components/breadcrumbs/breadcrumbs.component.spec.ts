import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BreadcrumbsComponent, BreadcrumbItem } from './breadcrumbs.component';

const THREE_ITEMS: readonly BreadcrumbItem[] = [
  { label: 'Home', href: '/' },
  { label: 'Users', href: '/users' },
  { label: 'Profile' },
];

describe('BreadcrumbsComponent', () => {
  let fixture: ComponentFixture<BreadcrumbsComponent>;
  let component: BreadcrumbsComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BreadcrumbsComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(BreadcrumbsComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.componentRef.setInput('items', THREE_ITEMS);
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should render a nav element with default aria-label when ariaLabel is not provided', () => {
    fixture.componentRef.setInput('items', THREE_ITEMS);
    fixture.detectChanges();

    const nav = fixture.nativeElement.querySelector('nav');
    expect(nav).toBeTruthy();
    expect(nav.getAttribute('aria-label')).toBe('Breadcrumb');
  });

  it('should apply custom ariaLabel when provided', () => {
    fixture.componentRef.setInput('items', THREE_ITEMS);
    fixture.componentRef.setInput('ariaLabel', 'Page navigation');
    fixture.detectChanges();

    const nav = fixture.nativeElement.querySelector('nav');
    expect(nav.getAttribute('aria-label')).toBe('Page navigation');
  });

  it('should apply testId to nav when testId input is set', () => {
    fixture.componentRef.setInput('items', THREE_ITEMS);
    fixture.componentRef.setInput('testId', 'main-breadcrumbs');
    fixture.detectChanges();

    const nav = fixture.nativeElement.querySelector(
      '[data-testid="main-breadcrumbs"]',
    );
    expect(nav).toBeTruthy();
  });

  it('should render the last item as a span with aria-current=page', () => {
    fixture.componentRef.setInput('items', THREE_ITEMS);
    fixture.detectChanges();

    const lastCrumb = fixture.nativeElement.querySelector(
      '[data-testid="crumb-2"]',
    );
    expect(lastCrumb.tagName.toLowerCase()).toBe('span');
    expect(lastCrumb.getAttribute('aria-current')).toBe('page');
    expect(lastCrumb.textContent.trim()).toBe('Profile');
  });

  it('should render non-last items with href as anchor links', () => {
    fixture.componentRef.setInput('items', THREE_ITEMS);
    fixture.detectChanges();

    const homeLink = fixture.nativeElement.querySelector(
      '[data-testid="crumb-0"]',
    );
    expect(homeLink.tagName.toLowerCase()).toBe('a');
    expect(homeLink.getAttribute('href')).toBe('/');
    expect(homeLink.textContent.trim()).toBe('Home');
  });

  it('should render non-last items without href as plain spans', () => {
    const items: readonly BreadcrumbItem[] = [
      { label: 'Section' },
      { label: 'Current' },
    ];
    fixture.componentRef.setInput('items', items);
    fixture.detectChanges();

    const sectionCrumb = fixture.nativeElement.querySelector(
      '[data-testid="crumb-0"]',
    );
    expect(sectionCrumb.tagName.toLowerCase()).toBe('span');
    expect(sectionCrumb.getAttribute('aria-current')).toBeNull();
  });

  it('should render separator slashes between non-last items', () => {
    fixture.componentRef.setInput('items', THREE_ITEMS);
    fixture.detectChanges();

    // Two separators for three items (after item 0 and item 1)
    const separators = fixture.nativeElement.querySelectorAll(
      '[aria-hidden="true"]',
    );
    expect(separators.length).toBe(2);
  });

  it('should not render a separator after the last item', () => {
    fixture.componentRef.setInput('items', [{ label: 'Only' }]);
    fixture.detectChanges();

    const separators = fixture.nativeElement.querySelectorAll(
      '[aria-hidden="true"]',
    );
    expect(separators.length).toBe(0);
  });

  it('should render a single-item breadcrumb as aria-current=page with no link', () => {
    fixture.componentRef.setInput('items', [
      { label: 'Dashboard', href: '/dashboard' },
    ]);
    fixture.detectChanges();

    const crumb = fixture.nativeElement.querySelector(
      '[data-testid="crumb-0"]',
    );
    // Even with href provided, single item is last — so span, not anchor
    expect(crumb.tagName.toLowerCase()).toBe('span');
    expect(crumb.getAttribute('aria-current')).toBe('page');
  });

  it('should display all labels in document order', () => {
    fixture.componentRef.setInput('items', THREE_ITEMS);
    fixture.detectChanges();

    const labels = ['Home', 'Users', 'Profile'];
    labels.forEach((label, i) => {
      const crumb = fixture.nativeElement.querySelector(
        `[data-testid="crumb-${i}"]`,
      );
      expect(crumb.textContent.trim()).toBe(label);
    });
  });
});
