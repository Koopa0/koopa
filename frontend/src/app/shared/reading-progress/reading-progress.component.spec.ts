import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { ReadingProgressComponent } from './reading-progress.component';

describe('ReadingProgressComponent', () => {
  describe('in browser', () => {
    let component: ReadingProgressComponent;
    let fixture: ComponentFixture<ReadingProgressComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [ReadingProgressComponent],
        providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
      }).compileComponents();

      fixture = TestBed.createComponent(ReadingProgressComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
    });

    it('should create', () => {
      expect(component).toBeTruthy();
    });

    it('should start with progress at 0', () => {
      expect(component['progress']()).toBe(0);
    });

    it('should render progress bar element', () => {
      const bar = fixture.nativeElement.querySelector('div > div');
      expect(bar).not.toBeNull();
    });
  });

  describe('on server', () => {
    let component: ReadingProgressComponent;
    let fixture: ComponentFixture<ReadingProgressComponent>;

    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [ReadingProgressComponent],
        providers: [{ provide: PLATFORM_ID, useValue: 'server' }],
      }).compileComponents();

      fixture = TestBed.createComponent(ReadingProgressComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
    });

    it('should create on server', () => {
      expect(component).toBeTruthy();
    });
  });
});
