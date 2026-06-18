import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ToastComponent } from './toast.component';
import type { Toast } from './toast.service';

const mockToast = (overrides: Partial<Toast> = {}): Toast => ({
  id: 1,
  title: 'Test notification',
  variant: 'default',
  duration: 4000,
  ...overrides,
});

describe('ToastComponent', () => {
  let fixture: ComponentFixture<ToastComponent>;
  let component: ToastComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ToastComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(ToastComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.componentRef.setInput('toast', mockToast());
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should display toast title', () => {
    fixture.componentRef.setInput('toast', mockToast({ title: 'File saved' }));
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('File saved');
  });

  it('should display description when desc is provided', () => {
    fixture.componentRef.setInput(
      'toast',
      mockToast({ title: 'Error', desc: 'Network failed' }),
    );
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Network failed');
  });

  it('should not render description element when desc is absent', () => {
    fixture.componentRef.setInput('toast', mockToast({ desc: undefined }));
    fixture.detectChanges();

    // The description div is only rendered inside @if (toast().desc); verify
    // no description-level text leaked (e.g. a stringified "undefined").
    const allText = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(allText).not.toContain('undefined');
  });

  it('should render the close button', () => {
    fixture.componentRef.setInput('toast', mockToast());
    fixture.componentRef.setInput('testId', 'my-toast');
    fixture.detectChanges();

    const closeBtn = fixture.nativeElement.querySelector(
      '[data-testid="my-toast-close"]',
    );
    expect(closeBtn).toBeTruthy();
  });

  it('should use default close button testid when testId is null', () => {
    fixture.componentRef.setInput('toast', mockToast());
    fixture.detectChanges();

    const closeBtn = fixture.nativeElement.querySelector(
      '[data-testid="toast-close"]',
    );
    expect(closeBtn).toBeTruthy();
  });

  it('should set testId attribute on the wrapper div when testId input is set', () => {
    fixture.componentRef.setInput('toast', mockToast());
    fixture.componentRef.setInput('testId', 'toast-42');
    fixture.detectChanges();

    const wrapper = fixture.nativeElement.querySelector(
      '[data-testid="toast-42"]',
    );
    expect(wrapper).toBeTruthy();
  });

  it('should emit dismiss with toast id when close button is clicked', () => {
    const toast = mockToast({ id: 7 });
    fixture.componentRef.setInput('toast', toast);
    fixture.componentRef.setInput('testId', 'toast-7');
    fixture.detectChanges();

    const spy = vi.fn();
    component.dismiss.subscribe(spy);

    const closeBtn = fixture.nativeElement.querySelector(
      '[data-testid="toast-7-close"]',
    ) as HTMLButtonElement;
    closeBtn.click();

    expect(spy).toHaveBeenCalledWith(7);
  });

  it('should use custom closeLabel for the close button aria-label', () => {
    fixture.componentRef.setInput('toast', mockToast());
    fixture.componentRef.setInput('closeLabel', 'Close alert');
    fixture.componentRef.setInput('testId', 'toast-cl');
    fixture.detectChanges();

    const closeBtn = fixture.nativeElement.querySelector(
      '[data-testid="toast-cl-close"]',
    ) as HTMLButtonElement;
    expect(closeBtn.getAttribute('aria-label')).toBe('Close alert');
  });

  it('should use default closeLabel when not provided', () => {
    fixture.componentRef.setInput('toast', mockToast());
    fixture.componentRef.setInput('testId', 'toast-def');
    fixture.detectChanges();

    const closeBtn = fixture.nativeElement.querySelector(
      '[data-testid="toast-def-close"]',
    ) as HTMLButtonElement;
    expect(closeBtn.getAttribute('aria-label')).toBe('Dismiss notification');
  });

  it('should apply success icon class when variant is success', () => {
    fixture.componentRef.setInput('toast', mockToast({ variant: 'success' }));
    fixture.detectChanges();

    const iconSpan = fixture.nativeElement.querySelector(
      'span[aria-hidden="true"]',
    ) as HTMLElement;
    expect(iconSpan.className).toContain('text-success');
  });

  it('should apply error icon class when variant is error', () => {
    fixture.componentRef.setInput('toast', mockToast({ variant: 'error' }));
    fixture.detectChanges();

    const iconSpan = fixture.nativeElement.querySelector(
      'span[aria-hidden="true"]',
    ) as HTMLElement;
    expect(iconSpan.className).toContain('text-error');
  });

  it('should apply brand icon class when variant is default', () => {
    fixture.componentRef.setInput('toast', mockToast({ variant: 'default' }));
    fixture.detectChanges();

    const iconSpan = fixture.nativeElement.querySelector(
      'span[aria-hidden="true"]',
    ) as HTMLElement;
    expect(iconSpan.className).toContain('text-brand');
  });
});
