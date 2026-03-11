import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { CollectedComponent } from './collected';

describe('CollectedComponent', () => {
  let component: CollectedComponent;
  let fixture: ComponentFixture<CollectedComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CollectedComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(CollectedComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
