import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { AccordionComponent } from './accordion.component';

@Component({
  imports: [AccordionComponent],
  template: `
    <app-accordion>
      <span data-testid="projected-content">Content A</span>
      <span data-testid="projected-content-b">Content B</span>
    </app-accordion>
  `,
})
class HostComponent {}

describe('AccordionComponent', () => {
  let fixture: ComponentFixture<HostComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(HostComponent);
    fixture.detectChanges();
  });

  it('should create', () => {
    const el = fixture.nativeElement.querySelector('[data-testid="accordion"]');
    expect(el).toBeTruthy();
  });

  it('should project slotted content into the container', () => {
    const el = fixture.nativeElement.querySelector('[data-testid="accordion"]');
    expect(el.querySelector('[data-testid="projected-content"]')).toBeTruthy();
    expect(
      el.querySelector('[data-testid="projected-content-b"]'),
    ).toBeTruthy();
  });

  it('should render a single container wrapping all projected nodes', () => {
    const containers = fixture.nativeElement.querySelectorAll(
      '[data-testid="accordion"]',
    );
    expect(containers.length).toBe(1);
  });
});
