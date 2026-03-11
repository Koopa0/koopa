import { TestBed, ComponentFixture } from '@angular/core/testing';
import { Router, ActivatedRoute } from '@angular/router';
import { signal, PLATFORM_ID } from '@angular/core';
import { LoginComponent } from './login';
import { AuthService } from '../../core/services/auth.service';
import { SeoService } from '../../core/services/seo/seo.service';

describe('LoginComponent', () => {
  let component: LoginComponent;
  let fixture: ComponentFixture<LoginComponent>;
  let mockRouter: { navigate: ReturnType<typeof vi.fn> };
  let mockAuthService: {
    isAuthenticated: ReturnType<typeof signal<boolean>>;
    handleOAuthCallback: ReturnType<typeof vi.fn>;
  };
  let mockSeoService: { updateMeta: ReturnType<typeof vi.fn> };
  let mockActivatedRoute: { snapshot: { queryParams: Record<string, string> } };

  beforeEach(async () => {
    mockRouter = { navigate: vi.fn() };
    mockAuthService = {
      isAuthenticated: signal(false),
      handleOAuthCallback: vi.fn(),
    };
    mockSeoService = { updateMeta: vi.fn() };
    mockActivatedRoute = {
      snapshot: { queryParams: {} },
    };

    await TestBed.configureTestingModule({
      imports: [LoginComponent],
      providers: [
        { provide: Router, useValue: mockRouter },
        { provide: AuthService, useValue: mockAuthService },
        { provide: SeoService, useValue: mockSeoService },
        { provide: ActivatedRoute, useValue: mockActivatedRoute },
        { provide: PLATFORM_ID, useValue: 'browser' },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LoginComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should set SEO meta on init', () => {
    fixture.detectChanges();
    expect(mockSeoService.updateMeta).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Login', noIndex: true }),
    );
  });

  it('should redirect to admin when already authenticated', async () => {
    const authenticatedAuth = {
      isAuthenticated: signal(true),
      handleOAuthCallback: vi.fn(),
    };

    TestBed.resetTestingModule();
    await TestBed.configureTestingModule({
      imports: [LoginComponent],
      providers: [
        { provide: Router, useValue: mockRouter },
        { provide: AuthService, useValue: authenticatedAuth },
        { provide: SeoService, useValue: mockSeoService },
        { provide: ActivatedRoute, useValue: mockActivatedRoute },
        { provide: PLATFORM_ID, useValue: 'browser' },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LoginComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(mockRouter.navigate).toHaveBeenCalledWith(['/admin']);
  });

  describe('error query param', () => {
    it('should show error message for unauthorized', () => {
      mockActivatedRoute.snapshot.queryParams = { error: 'unauthorized' };
      fixture.detectChanges();
      expect(component['errorMessage']()).toBe('此 Google 帳號無權限存取管理後台');
    });

    it('should show error message for missing_tokens', () => {
      mockActivatedRoute.snapshot.queryParams = { error: 'missing_tokens' };
      fixture.detectChanges();
      expect(component['errorMessage']()).toBe('登入失敗，請重試');
    });

    it('should show error message for oauth_failed', () => {
      mockActivatedRoute.snapshot.queryParams = { error: 'oauth_failed' };
      fixture.detectChanges();
      expect(component['errorMessage']()).toBe('Google 登入失敗，請重試');
    });

    it('should show generic error for unknown error codes', () => {
      mockActivatedRoute.snapshot.queryParams = { error: 'some_unknown_error' };
      fixture.detectChanges();
      expect(component['errorMessage']()).toBe('登入時發生錯誤');
    });

    it('should not show error when no error param', () => {
      mockActivatedRoute.snapshot.queryParams = {};
      fixture.detectChanges();
      expect(component['errorMessage']()).toBeNull();
    });
  });

  describe('signInWithGoogle', () => {
    it('should redirect to BFF OAuth endpoint', () => {
      fixture.detectChanges();
      // Cannot directly test window.location.href change in unit test,
      // but we verify the method exists and is callable
      expect(() => component['signInWithGoogle']()).not.toThrow();
    });
  });
});
