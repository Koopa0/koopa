import { Injectable, signal, DestroyRef, inject } from '@angular/core';

interface Notification {
  id: number;
  message: string;
  type: 'success' | 'error';
  timestamp: Date;
}

const AUTO_DISMISS_MS = 3000;

@Injectable({ providedIn: 'root' })
export class NotificationService {
  private readonly destroyRef = inject(DestroyRef);
  private nextId = 0;
  private readonly timers = new Map<number, ReturnType<typeof setTimeout>>();

  private readonly _notifications = signal<Notification[]>([]);
  readonly notifications = this._notifications.asReadonly();

  constructor() {
    this.destroyRef.onDestroy(() => {
      for (const timer of this.timers.values()) {
        clearTimeout(timer);
      }
      this.timers.clear();
    });
  }

  success(message: string): void {
    this.add(message, 'success');
  }

  error(message: string): void {
    this.add(message, 'error');
  }

  dismiss(id: number): void {
    this._notifications.update((list) => list.filter((n) => n.id !== id));
    const timer = this.timers.get(id);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(id);
    }
  }

  private add(message: string, type: 'success' | 'error'): void {
    const id = this.nextId++;
    const notification: Notification = {
      id,
      message,
      type,
      timestamp: new Date(),
    };

    this._notifications.update((list) => [...list, notification]);

    const timer = setTimeout(() => {
      this.dismiss(id);
    }, AUTO_DISMISS_MS);
    this.timers.set(id, timer);
  }
}
