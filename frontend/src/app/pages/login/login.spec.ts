import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
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
  let httpMock: HttpTestingController;

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
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: Router, useValue: mockRouter },
        { provide: AuthService, useValue: mockAuthService },
        { provide: SeoService, useValue: mockSeoService },
        { provide: ActivatedRoute, useValue: mockActivatedRoute },
        { provide: PLATFORM_ID, useValue: 'browser' },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LoginComponent);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
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
        provideHttpClient(),
        provideHttpClientTesting(),
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
    it('should fetch OAuth URL from BFF endpoint', () => {
      fixture.detectChanges();
      component['signInWithGoogle']();

      const req = httpMock.expectOne('/bff/api/auth/google');
      expect(req.request.method).toBe('GET');
      req.flush({ data: { url: 'https://accounts.google.com/o/oauth2/auth?...' } });
    });

    it('should set error message on HTTP failure', () => {
      fixture.detectChanges();
      component['signInWithGoogle']();

      const req = httpMock.expectOne('/bff/api/auth/google');
      req.flush('Error', { status: 500, statusText: 'Internal Server Error' });

      expect(component['errorMessage']()).toBe('無法取得登入連結，請稍後再試');
    });
  });
});
