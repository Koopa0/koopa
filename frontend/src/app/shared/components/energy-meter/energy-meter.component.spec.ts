import { Component, input } from '@angular/core';
import { TestBed, type ComponentFixture } from '@angular/core/testing';

import { EnergyMeterComponent } from './energy-meter.component';
import type { EnergyLevel } from '../../../core/models/workbench.model';

@Component({
  imports: [EnergyMeterComponent],
  template: `<app-energy-meter [level]="level()" />`,
})
class HostComponent {
  readonly level = input.required<EnergyLevel>();
}

describe('EnergyMeterComponent', () => {
  let fixture: ComponentFixture<HostComponent>;

  function render(level: EnergyLevel): HTMLElement {
    fixture = TestBed.createComponent(HostComponent);
    fixture.componentRef.setInput('level', level);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  function bars(el: HTMLElement): HTMLElement[] {
    return Array.from(el.querySelectorAll('[role="img"] > span'));
  }

  it('should light all three bars when level is high', () => {
    const lit = bars(render('high')).filter((b) =>
      b.className.includes('bg-warn'),
    );
    expect(lit.length).toBe(3);
  });

  it('should light two bars when level is medium', () => {
    const lit = bars(render('medium')).filter((b) =>
      b.className.includes('bg-info'),
    );
    expect(lit.length).toBe(2);
  });

  it('should light one bar when level is low', () => {
    const rendered = bars(render('low'));
    const lit = rendered.filter((b) => b.className.includes('bg-fg-subtle'));
    const unlit = rendered.filter((b) =>
      b.className.includes('bg-border-strong'),
    );
    expect(lit.length).toBe(1);
    expect(unlit.length).toBe(2);
  });

  it('should expose the level through the accessible label', () => {
    const el = render('high');
    const meter = el.querySelector('[role="img"]');
    expect(meter?.getAttribute('aria-label')).toBe('Energy: high');
  });
});
