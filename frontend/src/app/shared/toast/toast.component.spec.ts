import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ToastComponent } from './toast.component';
import { NotificationService } from '../../core/services/notification.service';

describe('ToastComponent', () => {
  let component: ToastComponent;
  let fixture: ComponentFixture<ToastComponent>;
  let notificationService: NotificationService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ToastComponent],
      providers: [provideNoopAnimations()],
    }).compileComponents();

    notificationService = TestBed.inject(NotificationService);
    fixture = TestBed.createComponent(ToastComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display notifications from service', () => {
    notificationService.success('Hello');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Hello');
  });

  it('should dismiss notification on button click', () => {
    notificationService.success('Dismiss me');
    fixture.detectChanges();
    const btn = fixture.nativeElement.querySelector(
      'button[aria-label="Close notification"]',
    );
    btn?.click();
    fixture.detectChanges();
    expect(notificationService.notifications().length).toBe(0);
  });
});
