import { TestBed } from '@angular/core/testing';
import { ToastService } from './toast.service';

describe('ToastService', () => {
  let service: ToastService;

  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({});
    service = TestBed.inject(ToastService);
  });

  afterEach(() => {
    service.clear();
    vi.useRealTimers();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should start with an empty toast list', () => {
    expect(service.toasts()).toHaveLength(0);
  });

  it('should add a toast when push is called', () => {
    service.push({ title: 'Hello', variant: 'default' });
    expect(service.toasts()).toHaveLength(1);
  });

  it('should use default variant when variant is omitted', () => {
    service.push({ title: 'No variant' });
    expect(service.toasts()[0].variant).toBe('default');
  });

  it('should store the provided variant', () => {
    service.push({ title: 'Done', variant: 'success' });
    expect(service.toasts()[0].variant).toBe('success');
  });

  it('should store title and optional desc', () => {
    service.push({
      title: 'Save failed',
      desc: 'Network error',
      variant: 'error',
    });
    const toast = service.toasts()[0];
    expect(toast.title).toBe('Save failed');
    expect(toast.desc).toBe('Network error');
  });

  it('should return the id of the pushed toast', () => {
    const id = service.push({ title: 'First' });
    expect(typeof id).toBe('number');
    expect(service.toasts()[0].id).toBe(id);
  });

  it('should assign unique ids for multiple pushes', () => {
    const id1 = service.push({ title: 'A' });
    const id2 = service.push({ title: 'B' });
    expect(id1).not.toBe(id2);
  });

  it('should accumulate multiple toasts', () => {
    service.push({ title: 'First' });
    service.push({ title: 'Second' });
    service.push({ title: 'Third' });
    expect(service.toasts()).toHaveLength(3);
  });

  it('should remove a toast when dismiss is called with its id', () => {
    const id = service.push({ title: 'Removable' });
    service.dismiss(id);
    expect(service.toasts()).toHaveLength(0);
  });

  it('should only remove the matching toast when multiple exist', () => {
    service.push({ title: 'Keep me' });
    const id = service.push({ title: 'Remove me' });
    service.push({ title: 'Keep me too' });

    service.dismiss(id);

    expect(service.toasts()).toHaveLength(2);
    expect(service.toasts().map((t) => t.title)).not.toContain('Remove me');
  });

  it('should auto-dismiss toast after default duration', async () => {
    service.push({ title: 'Auto-dismiss' });
    expect(service.toasts()).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(4000);

    expect(service.toasts()).toHaveLength(0);
  });

  it('should auto-dismiss after custom duration', async () => {
    service.push({ title: 'Short', duration: 1000 });

    await vi.advanceTimersByTimeAsync(999);
    expect(service.toasts()).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(1);
    expect(service.toasts()).toHaveLength(0);
  });

  it('should not auto-dismiss when duration is 0', async () => {
    service.push({ title: 'Persistent', duration: 0 });

    await vi.advanceTimersByTimeAsync(10000);

    expect(service.toasts()).toHaveLength(1);
  });

  it('should cancel pending timer when dismiss is called early', async () => {
    const id = service.push({ title: 'Early dismiss', duration: 4000 });

    await vi.advanceTimersByTimeAsync(1000);
    service.dismiss(id);

    await vi.advanceTimersByTimeAsync(3000);

    // Should not double-error or re-add: still zero toasts
    expect(service.toasts()).toHaveLength(0);
  });

  it('should remove all toasts when clear is called', () => {
    service.push({ title: 'A' });
    service.push({ title: 'B' });
    service.push({ title: 'C' });

    service.clear();

    expect(service.toasts()).toHaveLength(0);
  });

  it('should cancel all timers when clear is called', async () => {
    service.push({ title: 'A', duration: 2000 });
    service.push({ title: 'B', duration: 3000 });

    service.clear();

    await vi.advanceTimersByTimeAsync(5000);

    // Timers were cancelled; list should remain empty (not re-dismiss)
    expect(service.toasts()).toHaveLength(0);
  });
});
