import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { BackToTopComponent } from './back-to-top.component';

describe('BackToTopComponent', () => {
  describe('in browser', () => {
    let component: BackToTopComponent;
    let fixture: ComponentFixture<BackToTopComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [BackToTopComponent],
        providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
      }).compileComponents();

      fixture = TestBed.createComponent(BackToTopComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
    });

    it('should create', () => {
      expect(component).toBeTruthy();
    });

    it('should start as not visible', () => {
      expect(component['isVisible']()).toBe(false);
    });

    it('should have a button with aria-label', () => {
      const button = fixture.nativeElement.querySelector('button');
      expect(button).not.toBeNull();
      expect(button.getAttribute('aria-label')).toBe('Back to top');
    });
  });

  describe('on server', () => {
    let component: BackToTopComponent;
    let fixture: ComponentFixture<BackToTopComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [BackToTopComponent],
        providers: [{ provide: PLATFORM_ID, useValue: 'server' }],
      }).compileComponents();

      fixture = TestBed.createComponent(BackToTopComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
    });

    it('should create on server', () => {
      expect(component).toBeTruthy();
    });
  });
});
