import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ChipComponent } from './chip.component';

describe('ChipComponent', () => {
  let fixture: ComponentFixture<ChipComponent>;
  let component: ChipComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ChipComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(ChipComponent);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('testId', 'chip');
    fixture.detectChanges();
  });

  function chip(): HTMLSpanElement {
    return fixture.nativeElement.querySelector(
      '[data-testid="chip"]',
    ) as HTMLSpanElement;
  }

  function removeButton(): HTMLButtonElement | null {
    return fixture.nativeElement.querySelector(
      'button[aria-label="Remove"]',
    ) as HTMLButtonElement | null;
  }

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  describe('active input', () => {
    it('should not set data-active attribute when active is false', () => {
      fixture.componentRef.setInput('active', false);
      fixture.detectChanges();
      expect(chip().getAttribute('data-active')).toBeNull();
    });

    it('should set data-active="true" when active is true', () => {
      fixture.componentRef.setInput('active', true);
      fixture.detectChanges();
      expect(chip().getAttribute('data-active')).toBe('true');
    });
  });

  describe('testId input', () => {
    it('should not set data-testid when testId is null', () => {
      fixture.componentRef.setInput('testId', null);
      fixture.detectChanges();
      // span has no testid
      const span = fixture.nativeElement.querySelector('span');
      expect(span.getAttribute('data-testid')).toBeNull();
    });

    it('should set data-testid attribute when testId is provided', () => {
      fixture.componentRef.setInput('testId', 'lang-chip');
      fixture.detectChanges();
      expect(
        fixture.nativeElement
          .querySelector('[data-testid="lang-chip"]')
          .getAttribute('data-testid'),
      ).toBe('lang-chip');
    });

    it('should set data-testid on remove button derived from testId when removable', () => {
      fixture.componentRef.setInput('testId', 'lang-chip');
      fixture.componentRef.setInput('removable', true);
      fixture.detectChanges();
      const btn = fixture.nativeElement.querySelector(
        '[data-testid="lang-chip-remove"]',
      );
      expect(btn).toBeTruthy();
      expect(btn.getAttribute('data-testid')).toBe('lang-chip-remove');
    });
  });

  describe('removable input', () => {
    it('should not render remove button when removable is false', () => {
      fixture.componentRef.setInput('removable', false);
      fixture.detectChanges();
      expect(removeButton()).toBeNull();
    });

    it('should render remove button when removable is true', () => {
      fixture.componentRef.setInput('removable', true);
      fixture.detectChanges();
      expect(removeButton()).toBeTruthy();
    });

    it('should have aria-label="Remove" on the remove button', () => {
      fixture.componentRef.setInput('removable', true);
      fixture.detectChanges();
      expect(removeButton()?.getAttribute('aria-label')).toBe('Remove');
    });
  });

  describe('removed output', () => {
    it('should emit removed event when remove button is clicked', () => {
      fixture.componentRef.setInput('removable', true);
      fixture.detectChanges();

      const spy = vi.fn();
      component.removed.subscribe(spy);

      removeButton()!.click();

      expect(spy).toHaveBeenCalledTimes(1);
    });

    it('should not emit removed event when chip body is clicked (not remove button)', () => {
      fixture.componentRef.setInput('removable', true);
      fixture.detectChanges();

      const spy = vi.fn();
      component.removed.subscribe(spy);

      chip().click();

      expect(spy).not.toHaveBeenCalled();
    });
  });
});
