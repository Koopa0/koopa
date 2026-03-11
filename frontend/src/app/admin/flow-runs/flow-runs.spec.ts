import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { FlowRunsComponent } from './flow-runs';

describe('FlowRunsComponent', () => {
  let component: FlowRunsComponent;
  let fixture: ComponentFixture<FlowRunsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FlowRunsComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(FlowRunsComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
