import {
  Component,
  inject,
  signal,
  OnInit,
  ChangeDetectionStrategy,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Router, ActivatedRoute, RouterLink } from '@angular/router';
import { LucideAngularModule, AlertCircle, Home, Info } from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { SeoService } from '../../core/services/seo/seo.service';

const ERROR_MESSAGES: Record<string, string> = {
  unauthorized:
    'This Google account is not authorized to access the admin panel',
  missing_tokens: 'Login failed. Please try again',
  oauth_failed: 'Google login failed. Please try again',
};

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [RouterLink, LucideAngularModule],
  templateUrl: './login.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LoginComponent implements OnInit {
  private readonly http = inject(HttpClient);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly seoService = inject(SeoService);
  private readonly platformId = inject(PLATFORM_ID);

  protected readonly errorMessage = signal<string | null>(null);

  protected readonly AlertCircleIcon = AlertCircle;
  protected readonly HomeIcon = Home;
  protected readonly InfoIcon = Info;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Login',
      description: 'Admin login page',
      noIndex: true,
    });

    if (this.authService.isAuthenticated()) {
      this.router.navigate(['/admin']);
      return;
    }

    const error = this.route.snapshot.queryParams['error'];
    if (error) {
      this.errorMessage.set(
        ERROR_MESSAGES[error] ?? 'An error occurred during login',
      );
    }
  }

  protected signInWithGoogle(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    this.http.get<{ data: { url: string } }>('/bff/api/auth/google').subscribe({
      next: (res) => {
        const redirectUrl = new URL(res.data.url);
        const allowedOrigins = [
          'https://accounts.google.com',
          'https://github.com',
        ];
        if (allowedOrigins.some((origin) => redirectUrl.origin === origin)) {
          window.location.href = res.data.url;
        } else {
          this.errorMessage.set('Invalid redirect URL');
        }
      },
      error: () =>
        this.errorMessage.set(
          'Unable to get login link. Please try again later',
        ),
    });
  }
}
