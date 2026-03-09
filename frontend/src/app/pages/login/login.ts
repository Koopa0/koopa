import {
  Component,
  inject,
  signal,
  OnInit,
  ChangeDetectionStrategy,
} from '@angular/core';
import {
  FormBuilder,
  FormGroup,
  Validators,
  ReactiveFormsModule,
} from '@angular/forms';
import { Router, ActivatedRoute, RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  Mail,
  Lock,
  LogIn,
  EyeOff,
  Eye,
  AlertCircle,
  Home,
  Info,
} from 'lucide-angular';
import { AuthService } from '../../core/services/auth.service';
import type { LoginRequest } from '../../core/models';
import { SeoService } from '../../core/services/seo/seo.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [ReactiveFormsModule, RouterLink, LucideAngularModule],
  templateUrl: './login.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LoginComponent implements OnInit {
  private readonly fb = inject(FormBuilder);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly seoService = inject(SeoService);

  protected readonly loginForm: FormGroup;
  protected readonly isLoading = signal(false);
  protected readonly hidePassword = signal(true);
  protected readonly returnUrl = signal('/admin');
  protected readonly errorMessage = signal<string | null>(null);
  protected readonly successMessage = signal<string | null>(null);

  protected readonly MailIcon = Mail;
  protected readonly LockIcon = Lock;
  protected readonly LogInIcon = LogIn;
  protected readonly EyeOffIcon = EyeOff;
  protected readonly EyeIcon = Eye;
  protected readonly AlertCircleIcon = AlertCircle;
  protected readonly HomeIcon = Home;
  protected readonly InfoIcon = Info;

  constructor() {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]],
    });
  }

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

    const returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/admin';
    this.returnUrl.set(returnUrl);

    const error = this.route.snapshot.queryParams['error'];
    if (error === 'unauthorized') {
      this.errorMessage.set('You do not have permission to access this page');
    }
  }

  protected onSubmit(): void {
    if (this.loginForm.invalid) {
      this.markFormGroupTouched();
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);
    const credentials: LoginRequest = this.loginForm.value;

    this.authService.login(credentials).subscribe({
      next: () => {
        const user = this.authService.currentUser();
        this.successMessage.set(`Welcome back, ${user?.email ?? ''}!`);
        this.router.navigate([this.returnUrl()]);
      },
      error: (err) => {
        this.errorMessage.set(
          err.message || 'Login failed. Please check your email and password.',
        );
        this.isLoading.set(false);
      },
      complete: () => {
        this.isLoading.set(false);
      },
    });
  }

  protected togglePasswordVisibility(): void {
    this.hidePassword.set(!this.hidePassword());
  }

  private markFormGroupTouched(): void {
    Object.keys(this.loginForm.controls).forEach((key) => {
      const control = this.loginForm.get(key);
      control?.markAsTouched();
    });
  }

  protected getFieldError(fieldName: string): string {
    const control = this.loginForm.get(fieldName);
    if (control?.errors && control.touched) {
      if (control.errors['required']) {
        return 'This field is required';
      }
      if (control.errors['email']) {
        return 'Please enter a valid email address';
      }
      if (control.errors['minlength']) {
        const minLength = control.errors['minlength'].requiredLength;
        return `Must be at least ${minLength} characters`;
      }
    }
    return '';
  }
}
