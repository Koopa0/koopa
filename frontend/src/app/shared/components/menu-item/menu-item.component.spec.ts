import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { MenuItemComponent, type MenuItemVariant } from './menu-item.component';

@Component({
  imports: [MenuItemComponent],
  template: `
    <app-menu-item
      [variant]="variant()"
      [disabled]="disabled()"
      [testId]="testId()"
    >
      <svg menu-item-icon aria-hidden="true"><path d="M0 0" /></svg>
      {{ label() }}
    </app-menu-item>
  `,
})
class TestHostComponent {
  readonly variant = signal<MenuItemVariant>('default');
  readonly disabled = signal(false);
  readonly testId = signal<string | null>('test-menu-item');
  readonly label = signal('Edit item');
}

describe('MenuItemComponent', () => {
  let fixture: ComponentFixture<TestHostComponent>;
  let host: TestHostComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TestHostComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(TestHostComponent);
    host = fixture.componentInstance;
    await fixture.whenStable();
  });

  function button(): HTMLButtonElement {
    return fixture.nativeElement.querySelector(
      '[data-testid="test-menu-item"]',
    ) as HTMLButtonElement;
  }

  it('should create', () => {
    expect(fixture.nativeElement.querySelector('app-menu-item')).toBeTruthy();
  });

  it('should render label text when content is projected', () => {
    expect(button().textContent).toContain('Edit item');
  });

  it('should have role=menuitem', () => {
    expect(button().getAttribute('role')).toBe('menuitem');
  });

  it('should apply testId attribute when testId input is set', () => {
    expect(button()).toBeTruthy();
  });

  it('should not be disabled by default', () => {
    expect(button().disabled).toBe(false);
  });

  it('should be disabled when disabled input is true', async () => {
    host.disabled.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(button().disabled).toBe(true);
  });

  it('should set aria-disabled when disabled', async () => {
    host.disabled.set(true);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(button().getAttribute('aria-disabled')).toBe('true');
  });

  it('should not set aria-disabled when enabled', () => {
    expect(button().getAttribute('aria-disabled')).toBeNull();
  });

  it('should not apply danger text class for default variant', () => {
    const btn = button();
    expect(btn.className).not.toContain('text-error');
  });

  it('should apply danger text class when variant is danger', async () => {
    host.variant.set('danger');
    fixture.detectChanges();
    await fixture.whenStable();

    const btn = button();
    expect(btn.className).toContain('text-error');
  });

  it('should change from default to danger variant at runtime', async () => {
    const btnBefore = button();
    expect(btnBefore.className).not.toContain('text-error');

    host.variant.set('danger');
    fixture.detectChanges();
    await fixture.whenStable();

    expect(button().className).toContain('text-error');
  });
});
