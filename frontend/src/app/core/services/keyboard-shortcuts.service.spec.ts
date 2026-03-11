import { TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { Router } from '@angular/router';
import { KeyboardShortcutsService } from './keyboard-shortcuts.service';

describe('KeyboardShortcutsService', () => {
  let service: KeyboardShortcutsService;

  describe('in browser', () => {
    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [
          { provide: PLATFORM_ID, useValue: 'browser' },
          { provide: Router, useValue: { navigate: vi.fn() } },
        ],
      });
      service = TestBed.inject(KeyboardShortcutsService);
    });

    it('should be created', () => {
      expect(service).toBeTruthy();
    });

    it('should initialize without errors', () => {
      expect(() => service.init()).not.toThrow();
    });

    it('should handle multiple init calls without error', () => {
      service.init();
      expect(() => service.init()).not.toThrow();
    });
  });

  describe('on server', () => {
    beforeEach(() => {
      TestBed.configureTestingModule({
        providers: [
          { provide: PLATFORM_ID, useValue: 'server' },
          { provide: Router, useValue: { navigate: vi.fn() } },
        ],
      });
      service = TestBed.inject(KeyboardShortcutsService);
    });

    it('should be created on server', () => {
      expect(service).toBeTruthy();
    });

    it('should not throw on server when init is called', () => {
      expect(() => service.init()).not.toThrow();
    });
  });
});
