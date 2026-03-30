import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ActivatedRoute } from '@angular/router';
import { By } from '@angular/platform-browser';
import { JournalComponent } from './journal';

describe('JournalComponent', () => {
  let component: JournalComponent;
  let fixture: ComponentFixture<JournalComponent>;

  function createComponent(queryParams: Record<string, string> = {}): void {
    TestBed.configureTestingModule({
      imports: [JournalComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              queryParamMap: {
                get: (key: string) => queryParams[key] ?? null,
              },
            },
          },
        },
      ],
    });

    fixture = TestBed.createComponent(JournalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  }

  it('should create', () => {
    createComponent();
    expect(component).toBeTruthy();
  });

  it('should default to notes tab', () => {
    createComponent();
    const notesEl = fixture.debugElement.query(By.css('app-session-notes'));
    const planningEl = fixture.debugElement.query(By.css('app-planning'));
    expect(notesEl).toBeTruthy();
    expect(planningEl).toBeFalsy();
  });

  it('should start on analytics tab when query param is set', () => {
    createComponent({ tab: 'analytics' });
    const notesEl = fixture.debugElement.query(By.css('app-session-notes'));
    const planningEl = fixture.debugElement.query(By.css('app-planning'));
    expect(notesEl).toBeFalsy();
    expect(planningEl).toBeTruthy();
  });

  it('should switch to analytics tab when clicked', () => {
    createComponent();
    const tabButtons = fixture.debugElement.queryAll(By.css('nav button'));
    const analyticsTab = tabButtons[1];
    analyticsTab.nativeElement.click();
    fixture.detectChanges();

    const notesEl = fixture.debugElement.query(By.css('app-session-notes'));
    const planningEl = fixture.debugElement.query(By.css('app-planning'));
    expect(notesEl).toBeFalsy();
    expect(planningEl).toBeTruthy();
  });

  it('should pass hideHeader=true to child components', () => {
    createComponent();
    const notesEl = fixture.debugElement.query(By.css('app-session-notes'));
    expect(notesEl.componentInstance.hideHeader()).toBe(true);
  });
});
