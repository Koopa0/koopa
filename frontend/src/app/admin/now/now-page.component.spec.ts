import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { NowPageComponent } from './now-page.component';

describe('NowPageComponent', () => {
  it('should create the placeholder shell', () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        provideNoopAnimations(),
      ],
    });
    const fixture = TestBed.createComponent(NowPageComponent);
    expect(fixture.componentInstance).toBeTruthy();
  });
});
