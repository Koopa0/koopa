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
import {
  LucideAngularModule,
  AlertCircle,
  Home,
  Info,
} from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import { SeoService } from '../../core/services/seo/seo.service';

const ERROR_MESSAGES: Record<string, string> = {
  unauthorized: '此 Google 帳號無權限存取管理後台',
  missing_tokens: '登入失敗，請重試',
  oauth_failed: 'Google 登入失敗，請重試',
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
      this.errorMessage.set(ERROR_MESSAGES[error] ?? '登入時發生錯誤');
    }
  }

  protected signInWithGoogle(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    this.http
      .get<{ data: { url: string } }>('/bff/api/auth/google')
      .subscribe({
        next: (res) => (window.location.href = res.data.url),
        error: () => this.errorMessage.set('無法取得登入連結，請稍後再試'),
      });
  }
}
