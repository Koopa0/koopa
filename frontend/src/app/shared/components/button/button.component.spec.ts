import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ButtonComponent } from './button.component';

// Host used only for content-projection tests
@Component({
  template: `<app-button testId="host-btn">Projected</app-button>`,
  imports: [ButtonComponent],
})
class ProjectionHostComponent {}

describe('ButtonComponent', () => {
  let fixture: ComponentFixture<ButtonComponent>;
  let component: ButtonComponent;

  function btn(): HTMLButtonElement {
    return fixture.nativeElement.querySelector('button') as HTMLButtonElement;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ButtonComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(ButtonComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should set type="button" by default', () => {
    expect(btn().type).toBe('button');
  });

  it('should set type="submit" when type input is submit', () => {
    fixture.componentRef.setInput('type', 'submit');
    fixture.detectChanges();
    expect(btn().type).toBe('submit');
  });

  it('should set type="reset" when type input is reset', () => {
    fixture.componentRef.setInput('type', 'reset');
    fixture.detectChanges();
    expect(btn().type).toBe('reset');
  });

  it('should disable the button when disabled input is true', () => {
    fixture.componentRef.setInput('disabled', true);
    fixture.detectChanges();
    expect(btn().disabled).toBe(true);
  });

  it('should not disable the button when disabled is false', () => {
    fixture.componentRef.setInput('disabled', false);
    fixture.detectChanges();
    expect(btn().disabled).toBe(false);
  });

  it('should disable the button when loading is true', () => {
    fixture.componentRef.setInput('loading', true);
    fixture.detectChanges();
    expect(btn().disabled).toBe(true);
  });

  it('should set aria-busy when loading is true', () => {
    fixture.componentRef.setInput('loading', true);
    fixture.detectChanges();
    expect(btn().getAttribute('aria-busy')).toBe('true');
  });

  it('should not have aria-busy when loading is false', () => {
    fixture.componentRef.setInput('loading', false);
    fixture.detectChanges();
    expect(btn().getAttribute('aria-busy')).toBeNull();
  });

  it('should render a spinner element when loading is true', () => {
    fixture.componentRef.setInput('loading', true);
    fixture.detectChanges();
    const spinner = fixture.nativeElement.querySelector('span.animate-spin');
    expect(spinner).toBeTruthy();
  });

  it('should not render a spinner element when loading is false', () => {
    fixture.componentRef.setInput('loading', false);
    fixture.detectChanges();
    const spinner = fixture.nativeElement.querySelector('span.animate-spin');
    expect(spinner).toBeNull();
  });

  it('should forward testId to data-testid attribute when provided', () => {
    fixture.componentRef.setInput('testId', 'save-button');
    fixture.detectChanges();
    expect(btn().getAttribute('data-testid')).toBe('save-button');
  });

  it('should have no data-testid attribute when testId is null', () => {
    fixture.componentRef.setInput('testId', null);
    fixture.detectChanges();
    expect(btn().getAttribute('data-testid')).toBeNull();
  });

  it('should include w-full class when block is true', () => {
    fixture.componentRef.setInput('block', true);
    fixture.detectChanges();
    expect(btn().className).toContain('w-full');
  });

  it('should not include w-full class when block is false', () => {
    fixture.componentRef.setInput('block', false);
    fixture.detectChanges();
    expect(btn().className).not.toContain('w-full');
  });

  it('should apply primary variant class when variant is primary', () => {
    fixture.componentRef.setInput('variant', 'primary');
    fixture.detectChanges();
    expect(btn().className).toContain('bg-primary');
  });

  it('should apply danger variant class when variant is danger', () => {
    fixture.componentRef.setInput('variant', 'danger');
    fixture.detectChanges();
    expect(btn().className).toContain('bg-error-bg');
    expect(btn().className).toContain('text-error');
  });

  it('should apply ghost variant class when variant is ghost', () => {
    fixture.componentRef.setInput('variant', 'ghost');
    fixture.detectChanges();
    expect(btn().className).toContain('bg-transparent');
  });

  it('should apply secondary variant class by default', () => {
    // secondary is the default variant
    expect(btn().className).toContain('bg-elevated');
  });

  it('should apply xs size padding class when size is xs', () => {
    fixture.componentRef.setInput('size', 'xs');
    fixture.detectChanges();
    expect(btn().className).toContain('px-2');
    expect(btn().className).toContain('py-1');
  });

  it('should apply lg size padding class when size is lg', () => {
    fixture.componentRef.setInput('size', 'lg');
    fixture.detectChanges();
    expect(btn().className).toContain('py-2.5');
  });

  describe('content projection', () => {
    let hostFixture: ComponentFixture<ProjectionHostComponent>;

    beforeEach(async () => {
      hostFixture = TestBed.createComponent(ProjectionHostComponent);
      hostFixture.detectChanges();
    });

    it('should render projected label text when content is provided', () => {
      const innerBtn = hostFixture.nativeElement.querySelector('button');
      expect(innerBtn.textContent?.trim()).toBe('Projected');
    });
  });
});
