import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { NotificationService } from '../../core/services/notification.service';

@Component({
  selector: 'app-toast',
  standalone: true,
  templateUrl: './toast.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ToastComponent {
  protected readonly notificationService = inject(NotificationService);
  protected readonly notifications = this.notificationService.notifications;
}
