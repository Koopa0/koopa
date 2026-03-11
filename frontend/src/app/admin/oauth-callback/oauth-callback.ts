import {
  Component,
  inject,
  OnInit,
  ChangeDetectionStrategy,
} from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-oauth-callback',
  standalone: true,
  template: `
    <div class="flex min-h-[calc(100vh-4rem)] items-center justify-center bg-zinc-950">
      <div class="h-6 w-6 animate-spin rounded-full border-2 border-zinc-600 border-t-zinc-200"></div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export default class OAuthCallbackComponent implements OnInit {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  ngOnInit(): void {
    const params = this.route.snapshot.queryParams;
    const accessToken = params['access_token'];
    const refreshToken = params['refresh_token'];

    if (accessToken && refreshToken) {
      this.authService.handleOAuthCallback(accessToken, refreshToken);
      this.router.navigate(['/admin'], { replaceUrl: true });
    } else {
      this.router.navigate(['/login'], {
        queryParams: { error: params['error'] || 'missing_tokens' },
        replaceUrl: true,
      });
    }
  }
}
