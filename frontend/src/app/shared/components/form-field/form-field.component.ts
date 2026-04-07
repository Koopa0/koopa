import { Component, ChangeDetectionStrategy, input } from '@angular/core';

@Component({
  selector: 'app-form-field',
  standalone: true,
  template: `
    <div class="space-y-1.5">
      @if (label()) {
        <label
          [attr.for]="fieldId()"
          class="block text-sm font-medium text-zinc-300"
        >
          {{ label() }}
          @if (required()) {
            <span class="text-red-400">*</span>
          }
        </label>
      }
      @if (hint()) {
        <p class="text-xs text-zinc-500">{{ hint() }}</p>
      }
      <ng-content />
      @if (error()) {
        <p class="text-xs text-red-400" role="alert" aria-live="polite">
          {{ error() }}
        </p>
      }
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class FormFieldComponent {
  readonly label = input('');
  readonly fieldId = input('');
  readonly hint = input('');
  readonly error = input('');
  readonly required = input(false);
}
