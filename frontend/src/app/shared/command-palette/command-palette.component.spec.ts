import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { CommandPaletteComponent } from './command-palette.component';
import { CommandPaletteService } from './command-palette.service';

describe('CommandPaletteComponent', () => {
  let component: CommandPaletteComponent;
  let fixture: ComponentFixture<CommandPaletteComponent>;
  let service: CommandPaletteService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CommandPaletteComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(CommandPaletteComponent);
    component = fixture.componentInstance;
    service = TestBed.inject(CommandPaletteService);
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should not render dialog when closed', () => {
    const dialog = fixture.nativeElement.querySelector('[role="dialog"]');
    expect(dialog).toBeNull();
  });

  it('should render dialog when opened', () => {
    service.open();
    fixture.detectChanges();

    const dialog = fixture.nativeElement.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
  });

  it('should render search input when opened', () => {
    service.open();
    fixture.detectChanges();

    const input = fixture.nativeElement.querySelector('[data-testid="command-palette-input"]');
    expect(input).not.toBeNull();
  });

  it('should render action items when opened', () => {
    service.open();
    fixture.detectChanges();

    const results = fixture.nativeElement.querySelector('[data-testid="command-palette-results"]');
    expect(results).not.toBeNull();
    const buttons = results.querySelectorAll('[role="option"]');
    expect(buttons.length).toBeGreaterThan(0);
  });

  it('should close on Escape key', () => {
    service.open();
    fixture.detectChanges();

    const input = fixture.nativeElement.querySelector('[data-testid="command-palette-input"]');
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    fixture.detectChanges();

    expect(service.isOpen()).toBe(false);
  });
});
