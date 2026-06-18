import { Injectable, signal, type Signal } from '@angular/core';

export type ToastVariant = 'default' | 'success' | 'error';

export interface Toast {
  readonly id: number;
  readonly title: string;
  readonly desc?: string;
  readonly variant: ToastVariant;
  readonly duration: number;
}

export interface ToastInput {
  readonly title: string;
  readonly desc?: string;
  readonly variant?: ToastVariant;
  /** Auto-dismiss delay in ms; pass `0` to keep the toast until dismissed. */
  readonly duration?: number;
}

const DEFAULT_DURATION = 4000;

/**
 * DS toast queue — `ui-toast`. Root-provided store of active toasts driving
 * `app-toast-host`. `push()` enqueues and schedules auto-dismiss; `dismiss()`
 * removes by id (and clears its pending timer). Timers paired with signal
 * updates are zoneless-safe — the signal write triggers the render, not zone.js.
 */
@Injectable({ providedIn: 'root' })
export class ToastService {
  private readonly items = signal<readonly Toast[]>([]);
  private readonly timers = new Map<number, ReturnType<typeof setTimeout>>();
  private nextId = 0;

  /** Read-only view of the live toast stack for the host to render. */
  readonly toasts: Signal<readonly Toast[]> = this.items.asReadonly();

  push(input: ToastInput): number {
    const id = this.nextId++;
    const toast: Toast = {
      id,
      title: input.title,
      desc: input.desc,
      variant: input.variant ?? 'default',
      duration: input.duration ?? DEFAULT_DURATION,
    };
    this.items.update((list) => [...list, toast]);

    if (toast.duration > 0) {
      const timer = setTimeout(() => this.dismiss(id), toast.duration);
      this.timers.set(id, timer);
    }
    return id;
  }

  dismiss(id: number): void {
    const timer = this.timers.get(id);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.timers.delete(id);
    }
    this.items.update((list) => list.filter((t) => t.id !== id));
  }

  /** Remove every toast and cancel all pending auto-dismiss timers. */
  clear(): void {
    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }
    this.timers.clear();
    this.items.update(() => []);
  }
}
