import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { LatestPostsComponent } from './latest-posts.component';

describe('LatestPostsComponent', () => {
  let component: LatestPostsComponent;
  let fixture: ComponentFixture<LatestPostsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LatestPostsComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LatestPostsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
