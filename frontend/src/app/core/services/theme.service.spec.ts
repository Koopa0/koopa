import { TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { ThemeService } from './theme.service';

describe('ThemeService', () => {
  describe('in browser', () => {
    let service: ThemeService;

    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
      });
      service = TestBed.inject(ThemeService);
    });

    it('should be created', () => {
      expect(service).toBeTruthy();
    });

    it('should default to dark mode', () => {
      expect(service.isDarkMode()).toBe(true);
    });

    it('should set data-theme attribute to dark', () => {
      const theme = document.documentElement.getAttribute('data-theme');
      expect(theme).toBe('dark');
    });
  });

  describe('on server', () => {
    let service: ThemeService;

    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [{ provide: PLATFORM_ID, useValue: 'server' }],
      });
      service = TestBed.inject(ThemeService);
    });

    it('should be created on server', () => {
      expect(service).toBeTruthy();
    });

    it('should default to dark mode on server', () => {
      expect(service.isDarkMode()).toBe(true);
    });
  });
});
