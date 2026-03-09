import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ArticleDetailComponent } from './article-detail';

describe('ArticleDetailComponent', () => {
  let component: ArticleDetailComponent;
  let fixture: ComponentFixture<ArticleDetailComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ArticleDetailComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ArticleDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
