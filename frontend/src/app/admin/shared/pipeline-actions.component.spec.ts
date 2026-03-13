import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { PipelineActionsComponent } from './pipeline-actions.component';

describe('PipelineActionsComponent', () => {
  let fixture: ComponentFixture<PipelineActionsComponent>;
  let component: PipelineActionsComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PipelineActionsComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(PipelineActionsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render 5 pipeline buttons', () => {
    const buttons = fixture.nativeElement.querySelectorAll('button');
    expect(buttons.length).toBe(5);
  });

  it('should display button labels', () => {
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Obsidian');
    expect(el.textContent).toContain('RSS');
    expect(el.textContent).toContain('Notion');
    expect(el.textContent).toContain('Reconcile');
    expect(el.textContent).toContain('Bookmark');
  });
});
