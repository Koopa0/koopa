import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SendBackReasonDialogComponent } from './send-back-reason-dialog.component';

describe('SendBackReasonDialogComponent', () => {
  let fixture: ComponentFixture<SendBackReasonDialogComponent>;

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function textarea(): HTMLTextAreaElement {
    return el().querySelector<HTMLTextAreaElement>(
      '[data-testid="send-back-reason-textarea"]',
    )!;
  }

  function submitBtn(): HTMLButtonElement {
    return el().querySelector<HTMLButtonElement>(
      '[data-testid="send-back-submit"]',
    )!;
  }

  function cancelBtn(): HTMLButtonElement {
    return el().querySelector<HTMLButtonElement>(
      '[data-testid="send-back-cancel"]',
    )!;
  }

  function typeNote(value: string): void {
    const area = textarea();
    area.value = value;
    area.dispatchEvent(new Event('input'));
    fixture.detectChanges();
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SendBackReasonDialogComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(SendBackReasonDialogComponent);
    fixture.detectChanges();
  });

  it('should render the textarea and action buttons', () => {
    expect(textarea()).toBeTruthy();
    expect(submitBtn()).toBeTruthy();
    expect(cancelBtn()).toBeTruthy();
  });

  it('should disable submit when note is empty', () => {
    expect(submitBtn().disabled).toBe(true);
  });

  it('should disable submit when note is shorter than minimum length', () => {
    typeNote('Too short');
    expect(submitBtn().disabled).toBe(true);
  });

  it('should enable submit when note meets the minimum length', () => {
    typeNote('This is a sufficiently long revision note.');
    expect(submitBtn().disabled).toBe(false);
  });

  it('should emit submit with the trimmed note when confirmed', () => {
    const emitted: string[] = [];
    fixture.componentInstance.confirmed.subscribe((v) => emitted.push(v));

    typeNote('  Please add more detail to the introduction section.  ');
    submitBtn().click();

    expect(emitted).toEqual([
      'Please add more detail to the introduction section.',
    ]);
  });

  it('should not emit submit when note is invalid and submit is clicked', () => {
    const emitted: string[] = [];
    fixture.componentInstance.confirmed.subscribe((v) => emitted.push(v));

    typeNote('Short');
    submitBtn().click();

    expect(emitted).toEqual([]);
  });

  it('should emit cancel when the cancel button is clicked', () => {
    let cancelled = false;
    fixture.componentInstance.dismissed.subscribe(() => (cancelled = true));

    cancelBtn().click();

    expect(cancelled).toBe(true);
  });

  it('should disable both buttons while submitting', () => {
    fixture.componentRef.setInput('isSubmitting', true);
    fixture.detectChanges();

    expect(submitBtn().disabled).toBe(true);
    expect(cancelBtn().disabled).toBe(true);
  });

  it('should show a length hint only after typing but before reaching minimum', () => {
    expect(el().querySelector('#send-back-reason-hint')).toBeNull();

    typeNote('Short');
    expect(el().querySelector('#send-back-reason-hint')).toBeTruthy();

    typeNote('This meets the minimum length requirement for submission.');
    expect(el().querySelector('#send-back-reason-hint')).toBeNull();
  });
});
