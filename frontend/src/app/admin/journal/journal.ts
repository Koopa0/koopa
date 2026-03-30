import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { LucideAngularModule, Notebook, BarChart3 } from 'lucide-angular';
import { SessionNotesComponent } from '../session-notes/session-notes';
import { PlanningComponent } from '../planning/planning';

type ActiveTab = 'notes' | 'analytics';

@Component({
  selector: 'app-journal',
  standalone: true,
  imports: [LucideAngularModule, SessionNotesComponent, PlanningComponent],
  templateUrl: './journal.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class JournalComponent {
  protected readonly NotebookIcon = Notebook;
  protected readonly BarChart3Icon = BarChart3;

  protected readonly activeTab = signal<ActiveTab>('notes');

  constructor() {
    const tab = inject(ActivatedRoute).snapshot.queryParamMap.get('tab');
    if (tab === 'analytics') {
      this.activeTab.set('analytics');
    }
  }

  protected switchTab(tab: ActiveTab): void {
    this.activeTab.set(tab);
  }
}
