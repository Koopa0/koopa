import {
  Component,
  ChangeDetectionStrategy,
  output,
  signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, Plus } from 'lucide-angular';

@Component({
  selector: 'app-quick-capture',
  standalone: true,
  imports: [FormsModule, LucideAngularModule],
  templateUrl: './quick-capture.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class QuickCaptureComponent {
  readonly captured = output<string>();

  protected readonly PlusIcon = Plus;
  protected readonly text = signal('');

  protected submit(): void {
    const value = this.text().trim();
    if (value.length === 0) return;
    this.captured.emit(value);
    this.text.set('');
  }
}
