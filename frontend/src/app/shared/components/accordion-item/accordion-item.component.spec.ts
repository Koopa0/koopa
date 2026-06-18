import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { AccordionItemComponent } from './accordion-item.component';

// ---------------------------------------------------------------------------
// Host helpers
// ---------------------------------------------------------------------------

@Component({
  imports: [AccordionItemComponent],
  template: `
    <app-accordion-item title="Panel A">
      <p data-testid="panel-content">Panel body text</p>
    </app-accordion-item>
  `,
})
class DefaultHostComponent {}

@Component({
  imports: [AccordionItemComponent],
  template: `
    <app-accordion-item title="Open By Default" [defaultOpen]="true">
      <p data-testid="open-panel-content">Pre-opened body</p>
    </app-accordion-item>
  `,
})
class DefaultOpenHostComponent {}

@Component({
  imports: [AccordionItemComponent],
  template: `
    <app-accordion-item title="Disabled Item" [disabled]="true">
      <p data-testid="disabled-panel-content">Should not appear</p>
    </app-accordion-item>
  `,
})
class DisabledHostComponent {}

@Component({
  imports: [AccordionItemComponent],
  template: `
    <app-accordion-item title="Custom ID" testId="my-trigger">
      <p data-testid="custom-id-content">Custom testId body</p>
    </app-accordion-item>
  `,
})
class CustomTestIdHostComponent {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function trigger(fixture: ComponentFixture<unknown>): HTMLButtonElement {
  return fixture.nativeElement.querySelector(
    '[data-testid="accordion-trigger"]',
  ) as HTMLButtonElement;
}

function panel(fixture: ComponentFixture<unknown>): HTMLElement | null {
  return fixture.nativeElement.querySelector(
    '[data-testid="accordion-panel"]',
  ) as HTMLElement | null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AccordionItemComponent', () => {
  describe('default (closed) state', () => {
    let fixture: ComponentFixture<DefaultHostComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [DefaultHostComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(DefaultHostComponent);
      fixture.detectChanges();
    });

    it('should create', () => {
      expect(trigger(fixture)).toBeTruthy();
    });

    it('should render the title when provided', () => {
      expect(trigger(fixture).textContent).toContain('Panel A');
    });

    it('should be closed by default when defaultOpen is not set', () => {
      expect(trigger(fixture).getAttribute('aria-expanded')).toBe('false');
      expect(panel(fixture)).toBeNull();
    });

    it('should open the panel when trigger is clicked', () => {
      trigger(fixture).click();
      fixture.detectChanges();

      expect(trigger(fixture).getAttribute('aria-expanded')).toBe('true');
      expect(panel(fixture)).toBeTruthy();
    });

    it('should close the panel on a second click', () => {
      trigger(fixture).click();
      fixture.detectChanges();
      trigger(fixture).click();
      fixture.detectChanges();

      expect(trigger(fixture).getAttribute('aria-expanded')).toBe('false');
      expect(panel(fixture)).toBeNull();
    });

    it('should project content into the panel when open', () => {
      trigger(fixture).click();
      fixture.detectChanges();

      expect(
        fixture.nativeElement.querySelector('[data-testid="panel-content"]'),
      ).toBeTruthy();
    });

    it('should wire aria-controls to the panel id', () => {
      const btn = trigger(fixture);
      const panelId = btn.getAttribute('aria-controls');
      expect(panelId).toBeTruthy();

      trigger(fixture).click();
      fixture.detectChanges();

      const panelEl = panel(fixture);
      expect(panelEl?.id).toBe(panelId);
    });

    it('should have aria-labelledby on the panel pointing to the trigger', () => {
      trigger(fixture).click();
      fixture.detectChanges();

      const panelEl = panel(fixture);
      const triggerId = trigger(fixture).id;
      expect(panelEl?.getAttribute('aria-labelledby')).toBe(triggerId);
    });

    it('should set role="region" on the panel', () => {
      trigger(fixture).click();
      fixture.detectChanges();

      expect(panel(fixture)?.getAttribute('role')).toBe('region');
    });
  });

  describe('defaultOpen input', () => {
    let fixture: ComponentFixture<DefaultOpenHostComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [DefaultOpenHostComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(DefaultOpenHostComponent);
      fixture.detectChanges();
    });

    it('should be open on first render when defaultOpen is true', () => {
      expect(trigger(fixture).getAttribute('aria-expanded')).toBe('true');
      expect(panel(fixture)).toBeTruthy();
    });

    it('should project content immediately when defaultOpen is true', () => {
      expect(
        fixture.nativeElement.querySelector(
          '[data-testid="open-panel-content"]',
        ),
      ).toBeTruthy();
    });
  });

  describe('disabled input', () => {
    let fixture: ComponentFixture<DisabledHostComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [DisabledHostComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(DisabledHostComponent);
      fixture.detectChanges();
    });

    it('should have disabled attribute on button when disabled is true', () => {
      expect(trigger(fixture).disabled).toBe(true);
    });

    it('should not open panel when disabled trigger is clicked', () => {
      trigger(fixture).click();
      fixture.detectChanges();

      expect(panel(fixture)).toBeNull();
    });
  });

  describe('testId input', () => {
    let fixture: ComponentFixture<CustomTestIdHostComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [CustomTestIdHostComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(CustomTestIdHostComponent);
      fixture.detectChanges();
    });

    it('should use the custom testId on the trigger button', () => {
      const btn = fixture.nativeElement.querySelector(
        '[data-testid="my-trigger"]',
      );
      expect(btn).toBeTruthy();
      expect(btn.textContent).toContain('Custom ID');
    });
  });
});
