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
    <div
      class="flex min-h-[calc(100vh-4rem)] items-center justify-center bg-zinc-950"
    >
      <div
        class="size-6 animate-spin rounded-full border-2 border-zinc-600 border-t-zinc-200"
      ></div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export default class OAuthCallbackComponent implements OnInit {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  ngOnInit(): void {
    // Backend redirects with tokens in the URL fragment (#) to prevent them
    // from appearing in server logs and Referer headers.
    // Fall back to query params for error redirects (?error=...).
    const fragment = new URLSearchParams(window.location.hash.replace('#', ''));
    const accessToken = fragment.get('access_token');
    const refreshToken = fragment.get('refresh_token');

    // Clear tokens from URL to prevent leaking to browser history and Referer header
    window.history.replaceState({}, '', '/admin/oauth-callback');

    if (accessToken && refreshToken) {
      this.authService.handleOAuthCallback(accessToken, refreshToken);
      this.router.navigate(['/admin'], { replaceUrl: true });
    } else {
      const queryParams = this.route.snapshot.queryParams;
      this.router.navigate(['/login'], {
        queryParams: { error: queryParams['error'] || 'missing_tokens' },
        replaceUrl: true,
      });
    }
  }
}
