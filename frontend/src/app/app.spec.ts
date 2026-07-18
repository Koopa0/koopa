import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { AppComponent } from './app';

describe('AppComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AppComponent],
      providers: [
        provideRouter([{ path: '**', children: [] }]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it('should not render the command palette on the public site', async () => {
    await TestBed.inject(Router).navigateByUrl('/about');
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();

    expect(
      fixture.nativeElement.querySelector('app-command-palette'),
    ).toBeNull();
  });

  it('should keep the command palette in the admin area', async () => {
    await TestBed.inject(Router).navigateByUrl('/admin/daily/today');
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();

    expect(
      fixture.nativeElement.querySelector('app-command-palette'),
    ).not.toBeNull();
  });
});
