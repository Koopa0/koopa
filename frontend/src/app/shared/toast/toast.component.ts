import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import {
  trigger,
  transition,
  style,
  animate,
} from '@angular/animations';
import { NotificationService } from '../../core/services/notification.service';

const toastSlideIn = trigger('toastSlideIn', [
  transition(':enter', [
    style({ opacity: 0, transform: 'translateX(100%)' }),
    animate('250ms ease-out', style({ opacity: 1, transform: 'translateX(0)' })),
  ]),
  transition(':leave', [
    animate('200ms ease-in', style({ opacity: 0, transform: 'translateX(100%)' })),
  ]),
]);

@Component({
  selector: 'app-toast',
  standalone: true,
  templateUrl: './toast.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [toastSlideIn],
})
export class ToastComponent {
  protected readonly notificationService = inject(NotificationService);
  protected readonly notifications = this.notificationService.notifications;
}
