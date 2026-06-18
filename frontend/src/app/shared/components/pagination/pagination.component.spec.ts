import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PaginationComponent } from './pagination.component';

describe('PaginationComponent', () => {
  let fixture: ComponentFixture<PaginationComponent>;
  let component: PaginationComponent;

  function prevBtn(): HTMLButtonElement {
    return fixture.nativeElement.querySelector(
      '[data-testid="pagination-prev"]',
    ) as HTMLButtonElement;
  }

  function nextBtn(): HTMLButtonElement {
    return fixture.nativeElement.querySelector(
      '[data-testid="pagination-next"]',
    ) as HTMLButtonElement;
  }

  function pageBtn(page: number): HTMLButtonElement {
    return fixture.nativeElement.querySelector(
      `[data-testid="pagination-page-${page}"]`,
    ) as HTMLButtonElement;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PaginationComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(PaginationComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.componentRef.setInput('total', 50);
    fixture.componentRef.setInput('page', 1);
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should render a nav element with default aria-label', () => {
    fixture.componentRef.setInput('total', 50);
    fixture.componentRef.setInput('page', 1);
    fixture.detectChanges();

    const nav = fixture.nativeElement.querySelector('nav');
    expect(nav.getAttribute('aria-label')).toBe('Pagination');
  });

  it('should apply custom ariaLabel when provided', () => {
    fixture.componentRef.setInput('total', 50);
    fixture.componentRef.setInput('page', 1);
    fixture.componentRef.setInput('ariaLabel', 'Results navigation');
    fixture.detectChanges();

    const nav = fixture.nativeElement.querySelector('nav');
    expect(nav.getAttribute('aria-label')).toBe('Results navigation');
  });

  it('should apply testId to nav when testId input is set', () => {
    fixture.componentRef.setInput('total', 50);
    fixture.componentRef.setInput('page', 1);
    fixture.componentRef.setInput('testId', 'my-pagination');
    fixture.detectChanges();

    const nav = fixture.nativeElement.querySelector(
      '[data-testid="my-pagination"]',
    );
    expect(nav).toBeTruthy();
  });

  describe('prev/next button disabled state', () => {
    it('should disable prev button when on first page', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('page', 1);
      fixture.detectChanges();

      expect(prevBtn().disabled).toBe(true);
    });

    it('should enable prev button when not on first page', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('page', 2);
      fixture.detectChanges();

      expect(prevBtn().disabled).toBe(false);
    });

    it('should disable next button when on last page', () => {
      fixture.componentRef.setInput('total', 30);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 3);
      fixture.detectChanges();

      expect(nextBtn().disabled).toBe(true);
    });

    it('should enable next button when not on last page', () => {
      fixture.componentRef.setInput('total', 30);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 2);
      fixture.detectChanges();

      expect(nextBtn().disabled).toBe(false);
    });
  });

  describe('aria-current on current page button', () => {
    it('should mark current page button with aria-current=page', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 3);
      fixture.detectChanges();

      const currentBtn = pageBtn(3);
      expect(currentBtn.getAttribute('aria-current')).toBe('page');
    });

    it('should not mark other page buttons with aria-current', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 3);
      fixture.detectChanges();

      const page1 = pageBtn(1);
      expect(page1.getAttribute('aria-current')).toBeNull();
    });
  });

  describe('page model update', () => {
    it('should advance page model when next button is clicked', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 2);
      fixture.detectChanges();

      nextBtn().click();
      fixture.detectChanges();

      expect(component.page()).toBe(3);
    });

    it('should decrement page model when prev button is clicked', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 3);
      fixture.detectChanges();

      prevBtn().click();
      fixture.detectChanges();

      expect(component.page()).toBe(2);
    });

    it('should set page model to clicked page number', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 1);
      fixture.detectChanges();

      pageBtn(4).click();
      fixture.detectChanges();

      expect(component.page()).toBe(4);
    });

    it('should not change page model when clicking the already-current page', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 2);
      fixture.detectChanges();

      pageBtn(2).click();
      fixture.detectChanges();

      expect(component.page()).toBe(2);
    });
  });

  describe('token window and gaps', () => {
    it('should render all page buttons when total pages is small', () => {
      fixture.componentRef.setInput('total', 30);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 2);
      fixture.detectChanges();

      expect(pageBtn(1)).toBeTruthy();
      expect(pageBtn(2)).toBeTruthy();
      expect(pageBtn(3)).toBeTruthy();
    });

    it('should render gap ellipsis when pages exceed visible window', () => {
      fixture.componentRef.setInput('total', 100);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 5);
      fixture.detectChanges();

      const gaps = fixture.nativeElement.querySelectorAll(
        'span[aria-hidden="true"]',
      );
      expect(gaps.length).toBeGreaterThan(0);
    });

    it('should always render first and last page buttons when gap is shown', () => {
      fixture.componentRef.setInput('total', 100);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 5);
      fixture.detectChanges();

      expect(pageBtn(1)).toBeTruthy();
      expect(pageBtn(10)).toBeTruthy();
    });
  });

  describe('pageSize input', () => {
    it('should compute correct pageCount from total and pageSize', () => {
      fixture.componentRef.setInput('total', 25);
      fixture.componentRef.setInput('pageSize', 10);
      fixture.componentRef.setInput('page', 1);
      fixture.detectChanges();

      // 3 pages: 10 + 10 + 5
      expect(pageBtn(3)).toBeTruthy();
      expect(pageBtn(4)).toBeNull();
    });
  });

  describe('aria-label on prev/next buttons', () => {
    it('should use default prev/next labels', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('page', 2);
      fixture.detectChanges();

      expect(prevBtn().getAttribute('aria-label')).toBe('Previous page');
      expect(nextBtn().getAttribute('aria-label')).toBe('Next page');
    });

    it('should use custom prev/next labels when provided', () => {
      fixture.componentRef.setInput('total', 50);
      fixture.componentRef.setInput('page', 2);
      fixture.componentRef.setInput('prevLabel', 'Go back');
      fixture.componentRef.setInput('nextLabel', 'Go forward');
      fixture.detectChanges();

      expect(prevBtn().getAttribute('aria-label')).toBe('Go back');
      expect(nextBtn().getAttribute('aria-label')).toBe('Go forward');
    });
  });
});
