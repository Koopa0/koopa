import { TestBed } from '@angular/core/testing';
import { NotificationService } from './notification.service';

describe('NotificationService', () => {
  let service: NotificationService;

  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({});
    service = TestBed.inject(NotificationService);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should add success notification', () => {
    service.success('Done!');
    expect(service.notifications().length).toBe(1);
    expect(service.notifications()[0].type).toBe('success');
    expect(service.notifications()[0].message).toBe('Done!');
  });

  it('should add error notification', () => {
    service.error('Failed');
    expect(service.notifications().length).toBe(1);
    expect(service.notifications()[0].type).toBe('error');
  });

  it('should dismiss notification by id', () => {
    service.success('First');
    service.success('Second');
    const firstId = service.notifications()[0].id;
    service.dismiss(firstId);
    expect(service.notifications().length).toBe(1);
    expect(service.notifications()[0].message).toBe('Second');
  });

  it('should auto-dismiss after 3000ms', () => {
    service.success('Auto');
    expect(service.notifications().length).toBe(1);
    vi.advanceTimersByTime(3000);
    expect(service.notifications().length).toBe(0);
  });

  it('should assign incremental ids', () => {
    service.success('A');
    service.success('B');
    const ids = service.notifications().map((n) => n.id);
    expect(ids[1]).toBeGreaterThan(ids[0]);
  });
});
