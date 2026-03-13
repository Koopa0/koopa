import { ComponentFixture, TestBed } from '@angular/core/testing';
import { DeleteConfirmDialogComponent } from './delete-confirm-dialog.component';

describe('DeleteConfirmDialogComponent', () => {
  let fixture: ComponentFixture<DeleteConfirmDialogComponent>;
  let component: DeleteConfirmDialogComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DeleteConfirmDialogComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(DeleteConfirmDialogComponent);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('entityType', 'Article');
    fixture.componentRef.setInput('entityTitle', 'Test Article');
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display entity type and title', () => {
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Article');
    expect(el.textContent).toContain('Test Article');
  });

  it('should emit confirmed on confirm click', () => {
    const spy = vi.fn();
    component.confirmed.subscribe(spy);
    const confirmBtn = fixture.nativeElement.querySelector('button.bg-red-600');
    confirmBtn?.click();
    expect(spy).toHaveBeenCalled();
  });

  it('should emit cancelled on cancel click', () => {
    const spy = vi.fn();
    component.cancelled.subscribe(spy);
    const cancelBtn = fixture.nativeElement.querySelectorAll('button')[0];
    cancelBtn?.click();
    expect(spy).toHaveBeenCalled();
  });

  it('should disable buttons when deleting', () => {
    fixture.componentRef.setInput('isDeleting', true);
    fixture.detectChanges();
    const buttons = fixture.nativeElement.querySelectorAll('button');
    for (const btn of buttons) {
      expect(btn.disabled).toBe(true);
    }
  });

  it('should show deleting state', () => {
    fixture.componentRef.setInput('isDeleting', true);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Deleting...');
  });
});
