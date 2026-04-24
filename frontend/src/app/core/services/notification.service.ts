import { Injectable, signal, DestroyRef, inject } from '@angular/core';

type NotificationType = 'success' | 'error' | 'info' | 'undo';

interface Notification {
  id: number;
  message: string;
  type: NotificationType;
  timestamp: Date;
  /** Callback invoked when user clicks "Undo". Only for type='undo'. */
  onUndo?: () => void;
}

const AUTO_DISMISS_MS = 3000;
const UNDO_DISMISS_MS = 5000;

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

  info(message: string): void {
    this.add(message, 'info');
  }

  /**
   * Show an undo toast with a 5-second window.
   * If the user clicks "Undo", the onUndo callback fires.
   * If the toast auto-dismisses without undo, onCommit fires.
   */
  undo(message: string, onUndo: () => void, onCommit?: () => void): void {
    const id = this.nextId++;
    const notification: Notification = {
      id,
      message,
      type: 'undo',
      timestamp: new Date(),
      onUndo,
    };

    this._notifications.update((list) => [...list, notification]);

    const timer = setTimeout(() => {
      this.dismiss(id);
      onCommit?.();
    }, UNDO_DISMISS_MS);
    this.timers.set(id, timer);
  }

  /** Trigger undo on a notification and dismiss it. */
  triggerUndo(id: number): void {
    const notification = this._notifications().find((n) => n.id === id);
    if (notification?.onUndo) {
      notification.onUndo();
    }
    this.dismiss(id);
  }

  dismiss(id: number): void {
    this._notifications.update((list) => list.filter((n) => n.id !== id));
    const timer = this.timers.get(id);
    if (timer) {
      clearTimeout(timer);
      this.timers.delete(id);
    }
  }

  private add(message: string, type: NotificationType): void {
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
