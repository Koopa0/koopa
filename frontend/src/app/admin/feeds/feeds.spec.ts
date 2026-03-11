import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { FeedsComponent } from './feeds';

describe('FeedsComponent', () => {
  let component: FeedsComponent;
  let fixture: ComponentFixture<FeedsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FeedsComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(FeedsComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
