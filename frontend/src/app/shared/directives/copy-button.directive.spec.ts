import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { CopyButtonDirective } from './copy-button.directive';

@Component({
  standalone: true,
  imports: [CopyButtonDirective],
  template: `
    <pre appCopyButton>
      <code>const x = 1;</code>
    </pre>
  `,
})
class TestHostComponent {}

describe('CopyButtonDirective', () => {
  describe('in browser', () => {
    let fixture: ComponentFixture<TestHostComponent>;
    let preElement: HTMLPreElement;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [TestHostComponent],
        providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
      }).compileComponents();

      fixture = TestBed.createComponent(TestHostComponent);
      fixture.detectChanges();
      preElement = fixture.nativeElement.querySelector('pre');
    });

    it('should add a copy button to the pre element', () => {
      const button = preElement.querySelector('button');
      expect(button).not.toBeNull();
      expect(button?.textContent).toContain('複製');
    });

    it('should add group class and relative positioning', () => {
      expect(preElement.classList).toContain('group');
      expect(preElement.style.position).toBe('relative');
    });
  });

  describe('on server', () => {
    let fixture: ComponentFixture<TestHostComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [TestHostComponent],
        providers: [{ provide: PLATFORM_ID, useValue: 'server' }],
      }).compileComponents();

      fixture = TestBed.createComponent(TestHostComponent);
      fixture.detectChanges();
    });

    it('should not add a copy button on server', () => {
      const button = fixture.nativeElement.querySelector('pre button');
      expect(button).toBeNull();
    });
  });
});
