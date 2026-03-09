import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { ArticleEditorComponent } from './article-editor';

describe('ArticleEditorComponent', () => {
  let component: ArticleEditorComponent;
  let fixture: ComponentFixture<ArticleEditorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ArticleEditorComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ArticleEditorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
