import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterModule } from '@angular/router';
import { ErrorComponent } from './error.component';

describe('ErrorComponent', () => {
  let component: ErrorComponent;
  let fixture: ComponentFixture<ErrorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ErrorComponent, RouterModule.forRoot([])],
    }).compileComponents();

    fixture = TestBed.createComponent(ErrorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render error heading', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('發生錯誤');
  });

  it('should have reload button', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const buttons = compiled.querySelectorAll('button');
    const reloadButton = Array.from(buttons).find((b) =>
      b.textContent?.includes('重新載入'),
    );
    expect(reloadButton).toBeTruthy();
  });

  it('should have home link', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const homeLink = compiled.querySelector('a[href="/home"]');
    expect(homeLink).toBeTruthy();
  });
});
