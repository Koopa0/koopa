import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ToastHostComponent } from './toast-host.component';
import { ToastService } from '../toast/toast.service';

describe('ToastHostComponent', () => {
  let fixture: ComponentFixture<ToastHostComponent>;
  let service: ToastService;

  beforeEach(async () => {
    // Real timers here: with fake timers, Angular's zoneless scheduler (which
    // uses setTimeout) is frozen and fixture.whenStable() never resolves.
    await TestBed.configureTestingModule({
      imports: [ToastHostComponent],
    }).compileComponents();

    service = TestBed.inject(ToastService);
    fixture = TestBed.createComponent(ToastHostComponent);
    await fixture.whenStable();
  });

  afterEach(() => {
    service.clear();
  });

  function host(): HTMLElement {
    return fixture.nativeElement.querySelector(
      '[data-testid="toast-host"]',
    ) as HTMLElement;
  }
  function cards(): NodeListOf<Element> {
    return fixture.nativeElement.querySelectorAll('app-toast');
  }

  it('should create', () => {
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should render the host region with role=status', () => {
    expect(host().getAttribute('role')).toBe('status');
  });

  it('should render host region with aria-live=polite', () => {
    expect(host().getAttribute('aria-live')).toBe('polite');
  });

  it('should render no toast cards when service is empty', () => {
    expect(cards()).toHaveLength(0);
  });

  it('should render a toast card when service has one toast', async () => {
    service.push({ title: 'Hello', duration: 0 });
    await fixture.whenStable();
    expect(
      fixture.nativeElement.querySelector('[data-testid="toast-0"]'),
    ).toBeTruthy();
  });

  it('should display toast title text inside the card', async () => {
    service.push({ title: 'Upload complete', duration: 0 });
    await fixture.whenStable();
    const card = fixture.nativeElement.querySelector('[data-testid="toast-0"]');
    expect(card?.textContent).toContain('Upload complete');
  });

  it('should render multiple toast cards when service has multiple toasts', async () => {
    service.push({ title: 'First', duration: 0 });
    service.push({ title: 'Second', duration: 0 });
    service.push({ title: 'Third', duration: 0 });
    await fixture.whenStable();
    expect(cards()).toHaveLength(3);
  });

  it('should remove toast card from DOM when close button is clicked', async () => {
    service.push({ title: 'Closeable', duration: 0 });
    await fixture.whenStable();

    const closeBtn = fixture.nativeElement.querySelector(
      '[data-testid="toast-0-close"]',
    ) as HTMLButtonElement;
    closeBtn.click();
    await fixture.whenStable();

    expect(
      fixture.nativeElement.querySelector('[data-testid="toast-0"]'),
    ).toBeNull();
  });

  it('should auto-remove toast after its duration expires', async () => {
    // Fake timers ONLY here, and never whenStable() while they are active —
    // force CD with detectChanges() and advance the timer to fire dismiss.
    vi.useFakeTimers();
    try {
      service.push({ title: 'Auto', duration: 2000 });
      fixture.detectChanges();
      expect(
        fixture.nativeElement.querySelector('[data-testid="toast-0"]'),
      ).toBeTruthy();

      await vi.advanceTimersByTimeAsync(2000);
      fixture.detectChanges();
      expect(
        fixture.nativeElement.querySelector('[data-testid="toast-0"]'),
      ).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('should keep only remaining toasts after one is dismissed', async () => {
    service.push({ title: 'Keep', duration: 0 });
    const removeId = service.push({ title: 'Remove', duration: 0 });
    await fixture.whenStable();

    service.dismiss(removeId);
    await fixture.whenStable();

    expect(cards()).toHaveLength(1);
    expect(cards()[0].textContent).toContain('Keep');
  });
});
