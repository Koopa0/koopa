import { ComponentFixture, TestBed } from '@angular/core/testing';

import { WithdrawalReasonDialogComponent } from './withdrawal-reason-dialog.component';

describe('WithdrawalReasonDialogComponent', () => {
  let fixture: ComponentFixture<WithdrawalReasonDialogComponent>;

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function textarea(): HTMLTextAreaElement {
    return el().querySelector<HTMLTextAreaElement>(
      '[data-testid="withdraw-reason-textarea"]',
    )!;
  }

  function submit(): HTMLButtonElement {
    return el().querySelector<HTMLButtonElement>(
      '[data-testid="withdraw-submit"]',
    )!;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [WithdrawalReasonDialogComponent],
    }).compileComponents();
    fixture = TestBed.createComponent(WithdrawalReasonDialogComponent);
    fixture.detectChanges();
  });

  it('requires a non-blank reason and emits its trimmed value', () => {
    const emitted: string[] = [];
    fixture.componentInstance.confirmed.subscribe((value) => emitted.push(value));

    expect(submit().disabled).toBe(true);
    textarea().value = '   ';
    textarea().dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(submit().disabled).toBe(true);

    textarea().value = '  Contains private contact details.  ';
    textarea().dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(submit().disabled).toBe(false);
    submit().click();

    expect(emitted).toEqual(['Contains private contact details.']);
  });

  it('explains that withdrawal cannot recall third-party copies', () => {
    expect(el().textContent).toContain('cannot recall copies already received');
  });
});
