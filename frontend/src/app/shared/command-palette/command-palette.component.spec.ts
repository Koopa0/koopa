import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { AuthService } from '../../core/services/auth.service';
import { NotificationService } from '../../core/services/notification.service';
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
        provideHttpClient(withXhr()),
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

  describe('capture mode (GTD inbox fallback)', () => {
    // Structurally valid JWT (header.payload.signature, base64url JSON
    // payload) so AuthService.decodeUser succeeds. Signature is not
    // verified client-side.
    const fakeAccessToken = [
      btoa(JSON.stringify({ alg: 'none', typ: 'JWT' })),
      btoa(JSON.stringify({ email: 'koopa@example.com' })),
      'sig',
    ].join('.');

    /**
     * Authenticate via the real AuthService (memory token, no HTTP),
     * open the palette, flush the admin entity-load requests, and type
     * a query that matches no command or entity. Only the HTTP layer
     * is mocked (provideHttpClientTesting); TodoService, AuthService
     * and NotificationService are the real implementations.
     */
    function enterCaptureState(query: string): {
      httpMock: HttpTestingController;
      input: HTMLInputElement;
    } {
      const httpMock = TestBed.inject(HttpTestingController);
      TestBed.inject(AuthService).handleOAuthCallback(
        fakeAccessToken,
        'refresh',
      );

      service.open();
      fixture.detectChanges();

      httpMock.expectOne('/bff/api/admin/commitment/goals').flush([]);
      httpMock
        .expectOne('/bff/api/admin/commitment/projects')
        .flush({ data: [] });
      httpMock
        .expectOne((r) => r.url.includes('/bff/api/admin/knowledge/content'))
        .flush({ data: [] });
      fixture.detectChanges();

      const input = fixture.nativeElement.querySelector(
        '[data-testid="command-palette-input"]',
      ) as HTMLInputElement;
      input.value = query;
      input.dispatchEvent(new Event('input'));
      fixture.detectChanges();

      return { httpMock, input };
    }

    it('should offer the capture action when the query matches nothing', () => {
      enterCaptureState('water the bonsai');

      const captureButton = fixture.nativeElement.querySelector(
        '[data-testid="command-palette-capture"]',
      );
      expect(captureButton).not.toBeNull();
      expect(captureButton.textContent).toContain('Capture to GTD Inbox');
      expect(captureButton.textContent).toContain('water the bonsai');

      const pill = fixture.nativeElement.querySelector(
        '[data-testid="command-palette-capture-pill"]',
      );
      expect(pill).not.toBeNull();
    });

    it('should create an inbox todo, toast, and close when capture is clicked', () => {
      const { httpMock } = enterCaptureState('water the bonsai');
      const notifications = TestBed.inject(NotificationService);

      const captureButton = fixture.nativeElement.querySelector(
        '[data-testid="command-palette-capture"]',
      ) as HTMLButtonElement;
      captureButton.click();

      const req = httpMock.expectOne('/bff/api/admin/commitment/todos');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        title: 'water the bonsai',
        state: 'inbox',
      });
      req.flush({ id: 't1', title: 'water the bonsai', state: 'inbox' });
      fixture.detectChanges();

      expect(service.isOpen()).toBe(false);
      expect(
        notifications
          .notifications()
          .some((n) => n.message === 'Captured to inbox: "water the bonsai"'),
      ).toBe(true);
    });

    it('should capture on Enter when nothing matches', () => {
      const { httpMock, input } = enterCaptureState('zzz nothing matches');

      input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
      fixture.detectChanges();

      const req = httpMock.expectOne('/bff/api/admin/commitment/todos');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        title: 'zzz nothing matches',
        state: 'inbox',
      });
      req.flush({ id: 't2', title: 'zzz nothing matches', state: 'inbox' });
      fixture.detectChanges();

      expect(service.isOpen()).toBe(false);
    });

    it('should keep the palette open and toast an error when capture fails', () => {
      const { httpMock } = enterCaptureState('doomed capture');
      const notifications = TestBed.inject(NotificationService);

      const captureButton = fixture.nativeElement.querySelector(
        '[data-testid="command-palette-capture"]',
      ) as HTMLButtonElement;
      captureButton.click();

      httpMock
        .expectOne('/bff/api/admin/commitment/todos')
        .flush(null, { status: 500, statusText: 'Internal Server Error' });
      fixture.detectChanges();

      expect(service.isOpen()).toBe(true);
      expect(
        notifications.notifications().some((n) => n.type === 'error'),
      ).toBe(true);
    });

    it('should NOT offer capture when unauthenticated', () => {
      service.open();
      fixture.detectChanges();

      const input = fixture.nativeElement.querySelector(
        '[data-testid="command-palette-input"]',
      ) as HTMLInputElement;
      input.value = 'zzz nothing matches';
      input.dispatchEvent(new Event('input'));
      fixture.detectChanges();

      const captureButton = fixture.nativeElement.querySelector(
        '[data-testid="command-palette-capture"]',
      );
      expect(captureButton).toBeNull();
    });
  });
});
