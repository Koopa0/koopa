import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { By } from '@angular/platform-browser';
import { InboxComponent } from './inbox';

describe('InboxComponent', () => {
  let component: InboxComponent;
  let fixture: ComponentFixture<InboxComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [InboxComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(InboxComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should default to collected tab', () => {
    const collectedEl = fixture.debugElement.query(By.css('app-collected'));
    const reviewEl = fixture.debugElement.query(By.css('app-review'));
    expect(collectedEl).toBeTruthy();
    expect(reviewEl).toBeFalsy();
  });

  it('should switch to review tab when clicked', () => {
    const tabButtons = fixture.debugElement.queryAll(By.css('nav button'));
    const reviewTab = tabButtons[1];
    reviewTab.nativeElement.click();
    fixture.detectChanges();

    const collectedEl = fixture.debugElement.query(By.css('app-collected'));
    const reviewEl = fixture.debugElement.query(By.css('app-review'));
    expect(collectedEl).toBeFalsy();
    expect(reviewEl).toBeTruthy();
  });

  it('should pass hideHeader=true to child components', () => {
    const collectedEl = fixture.debugElement.query(By.css('app-collected'));
    expect(collectedEl.componentInstance.hideHeader()).toBe(true);
  });
});
