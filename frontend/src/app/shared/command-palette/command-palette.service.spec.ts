import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { CommandPaletteService } from './command-palette.service';

describe('CommandPaletteService', () => {
  let service: CommandPaletteService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    });
    service = TestBed.inject(CommandPaletteService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should start closed', () => {
    expect(service.isOpen()).toBe(false);
  });

  it('should open and close', () => {
    service.open();
    expect(service.isOpen()).toBe(true);

    service.close();
    expect(service.isOpen()).toBe(false);
  });

  it('should toggle', () => {
    service.toggle();
    expect(service.isOpen()).toBe(true);

    service.toggle();
    expect(service.isOpen()).toBe(false);
  });

  it('should have page actions', () => {
    const actions = service.actions();
    const pageActions = actions.filter((a) => a.group === 'Pages');
    expect(pageActions.length).toBeGreaterThan(0);
    expect(pageActions.some((a) => a.id === 'home')).toBe(true);
    expect(pageActions.some((a) => a.id === 'articles')).toBe(true);
  });

  it('should not have admin actions when unauthenticated', () => {
    const actions = service.actions();
    const adminActions = actions.filter((a) => a.group === 'Admin');
    expect(adminActions.length).toBe(0);
  });
});
