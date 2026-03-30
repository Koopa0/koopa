import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import {
  LucideAngularModule,
  Inbox,
  Database,
  ClipboardCheck,
} from 'lucide-angular';
import { CollectedComponent } from '../collected/collected';
import { ReviewComponent } from '../review/review';

type ActiveTab = 'collected' | 'review';

@Component({
  selector: 'app-inbox',
  standalone: true,
  imports: [LucideAngularModule, CollectedComponent, ReviewComponent],
  templateUrl: './inbox.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class InboxComponent {
  protected readonly InboxIcon = Inbox;
  protected readonly DatabaseIcon = Database;
  protected readonly ClipboardCheckIcon = ClipboardCheck;

  protected readonly activeTab = signal<ActiveTab>('collected');

  protected switchTab(tab: ActiveTab): void {
    this.activeTab.set(tab);
  }
}
