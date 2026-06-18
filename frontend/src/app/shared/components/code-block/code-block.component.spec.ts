import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Clipboard } from '@angular/cdk/clipboard';
import { CodeBlockComponent } from './code-block.component';

describe('CodeBlockComponent', () => {
  let fixture: ComponentFixture<CodeBlockComponent>;
  let copySpy: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    copySpy = vi.fn().mockReturnValue(true);
    await TestBed.configureTestingModule({
      imports: [CodeBlockComponent],
      providers: [{ provide: Clipboard, useValue: { copy: copySpy } }],
    }).compileComponents();

    fixture = TestBed.createComponent(CodeBlockComponent);
    fixture.componentRef.setInput('code', 'const x = 1;');
    fixture.componentRef.setInput('lang', 'ts');
    await fixture.whenStable();
  });

  function copyButton(): HTMLButtonElement {
    return fixture.nativeElement.querySelector(
      '[data-testid="code-block-copy"]',
    );
  }

  it('should render the code and language', () => {
    expect(fixture.nativeElement.querySelector('code').textContent).toContain(
      'const x = 1;',
    );
    expect(fixture.nativeElement.textContent).toContain('ts');
  });

  it('should show the Copy affordance before any copy', () => {
    expect(copyButton().textContent).toContain('Copy');
    expect(copyButton().getAttribute('aria-label')).toBe('Copy code');
  });

  it('should copy the code to the clipboard when the button is clicked', () => {
    copyButton().click();
    expect(copySpy).toHaveBeenCalledWith('const x = 1;');
  });

  it('should flip to the Copied state after a successful copy', async () => {
    copyButton().click();
    await fixture.whenStable();
    expect(copyButton().textContent).toContain('Copied');
    expect(copyButton().getAttribute('aria-label')).toBe('Copied to clipboard');
  });

  it('should revert to Copy after the reset timeout', async () => {
    vi.useFakeTimers();
    try {
      copyButton().click();
      fixture.detectChanges();
      expect(copyButton().textContent).toContain('Copied');
      await vi.advanceTimersByTimeAsync(2000);
      fixture.detectChanges();
      expect(copyButton().textContent).toContain('Copy');
      expect(copyButton().textContent).not.toContain('Copied');
    } finally {
      vi.useRealTimers();
    }
  });

  it('should not enter the Copied state when the clipboard copy fails', async () => {
    copySpy.mockReturnValue(false);
    copyButton().click();
    await fixture.whenStable();
    expect(copyButton().textContent).toContain('Copy');
    expect(copyButton().textContent).not.toContain('Copied');
  });

  it('should suffix the copy button testid when a testId is provided', async () => {
    fixture.componentRef.setInput('testId', 'snippet');
    await fixture.whenStable();
    expect(
      fixture.nativeElement.querySelector('[data-testid="snippet-copy"]'),
    ).not.toBeNull();
    expect(
      fixture.nativeElement.querySelector('[data-testid="snippet"]'),
    ).not.toBeNull();
  });
});
