import { Component, ChangeDetectionStrategy, input } from '@angular/core';

export interface StepItem {
  readonly label: string;
}

type StepState = 'done' | 'current' | 'upcoming';

const DOT_CLASSES: Record<StepState, string> = {
  done: 'bg-primary text-primary-foreground border-2 border-transparent',
  current: 'bg-(--accent-faint) border-2 border-primary text-brand-strong',
  upcoming: 'bg-elevated border-2 border-border text-fg-subtle',
};

/**
 * DS stepper — `ui-stepper`. Horizontal progress indicator: 28px round dots
 * connected by a rule that fills with the accent up to the current step.
 * `current` is the zero-based index of the active step (aria-current=step).
 */
@Component({
  selector: 'app-stepper',
  template: `
    <ol
      class="m-0 flex list-none items-start p-0"
      [attr.data-testid]="'stepper'"
    >
      @for (
        step of steps();
        track step.label;
        let i = $index;
        let last = $last
      ) {
        <li class="flex flex-1 flex-col items-center gap-2 last:flex-none">
          <div class="flex w-full items-center">
            <!-- leading connector -->
            @if (i > 0) {
              <span
                class="h-0.5 flex-1"
                [class]="i <= current() ? 'bg-primary' : 'bg-border'"
                aria-hidden="true"
              ></span>
            } @else {
              <span class="flex-1" aria-hidden="true"></span>
            }
            <span
              class="flex size-7 shrink-0 items-center justify-center rounded-full font-mono text-xs leading-none font-medium transition-colors duration-[120ms]"
              [class]="dotClasses(i)"
              [attr.aria-current]="i === current() ? 'step' : null"
              [attr.data-testid]="'stepper-dot-' + i"
            >
              @if (stateOf(i) === 'done') {
                <svg
                  class="size-3.5"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="3"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <path d="M20 6 9 17l-5-5" />
                </svg>
              } @else {
                {{ i + 1 }}
              }
            </span>
            <!-- trailing connector -->
            @if (!last) {
              <span
                class="h-0.5 flex-1"
                [class]="i < current() ? 'bg-primary' : 'bg-border'"
                aria-hidden="true"
              ></span>
            } @else {
              <span class="flex-1" aria-hidden="true"></span>
            }
          </div>
          <span
            class="px-1 text-center font-sans text-xs leading-tight"
            [class]="i === current() ? 'text-brand-strong' : 'text-fg-subtle'"
          >
            {{ step.label }}
          </span>
        </li>
      }
    </ol>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StepperComponent {
  readonly steps = input.required<readonly StepItem[]>();
  readonly current = input(0);

  protected stateOf(index: number): StepState {
    const c = this.current();
    if (index < c) {
      return 'done';
    }
    return index === c ? 'current' : 'upcoming';
  }

  protected dotClasses(index: number): string {
    return DOT_CLASSES[this.stateOf(index)];
  }
}
