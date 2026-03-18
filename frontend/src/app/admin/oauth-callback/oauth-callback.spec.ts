import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { ActivatedRoute } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import OAuthCallbackComponent from './oauth-callback';

describe('OAuthCallbackComponent', () => {
  function setup(
    hash: string,
    queryParams: Record<string, string> = {},
  ) {
    // Simulate URL fragment
    Object.defineProperty(window, 'location', {
      value: { ...window.location, hash },
      writable: true,
    });

    TestBed.configureTestingModule({
      imports: [OAuthCallbackComponent],
      providers: [
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParams } },
        },
        {
          provide: AuthService,
          useValue: { handleOAuthCallback: vi.fn() },
        },
      ],
    });
    const fixture = TestBed.createComponent(OAuthCallbackComponent);
    const router = TestBed.inject(Router);
    const authService = TestBed.inject(AuthService);
    vi.spyOn(router, 'navigate');
    vi.spyOn(window.history, 'replaceState').mockReturnValue(undefined);
    return { fixture, router, authService };
  }

  it('should navigate to admin when tokens present in fragment', () => {
    const { fixture, router, authService } = setup(
      '#access_token=at&refresh_token=rt',
    );
    fixture.detectChanges();
    expect(authService.handleOAuthCallback).toHaveBeenCalledWith('at', 'rt');
    expect(router.navigate).toHaveBeenCalledWith(['/admin'], {
      replaceUrl: true,
    });
  });

  it('should navigate to login when tokens missing', () => {
    const { fixture, router } = setup('');
    fixture.detectChanges();
    expect(router.navigate).toHaveBeenCalledWith(['/login'], {
      queryParams: { error: 'missing_tokens' },
      replaceUrl: true,
    });
  });

  it('should forward error query param to login', () => {
    const { fixture, router } = setup('', { error: 'access_denied' });
    fixture.detectChanges();
    expect(router.navigate).toHaveBeenCalledWith(['/login'], {
      queryParams: { error: 'access_denied' },
      replaceUrl: true,
    });
  });
});
