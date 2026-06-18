import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CardComponent } from './card.component';

// Host used only for content-projection tests (body + slots)
@Component({
  template: `
    <app-card
      title="Projected Title"
      description="Projected desc"
      testId="proj-card"
    >
      <span data-testid="card-body">Body content</span>
      <div card-actions>
        <button data-testid="card-action-btn">Action</button>
      </div>
      <div card-footer data-testid="card-footer-slot">Footer</div>
    </app-card>
  `,
  imports: [CardComponent],
})
class ProjectionHostComponent {}

describe('CardComponent', () => {
  let fixture: ComponentFixture<CardComponent>;
  let component: CardComponent;

  function cardEl(): HTMLElement {
    return fixture.nativeElement.querySelector('div') as HTMLElement;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CardComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(CardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should not render title element when title input is null', () => {
    // title defaults to null
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('h3')).toBeNull();
  });

  it('should render title text when title input is provided', () => {
    fixture.componentRef.setInput('title', 'My Card');
    fixture.detectChanges();
    const h3 = fixture.nativeElement.querySelector('h3');
    expect(h3).toBeTruthy();
    expect(h3.textContent).toContain('My Card');
  });

  it('should not render description when description is null', () => {
    fixture.componentRef.setInput('title', 'Title');
    fixture.componentRef.setInput('description', null);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('p')).toBeNull();
  });

  it('should render description text when description input is provided', () => {
    fixture.componentRef.setInput('title', 'Title');
    fixture.componentRef.setInput('description', 'A description');
    fixture.detectChanges();
    const p = fixture.nativeElement.querySelector('p');
    expect(p).toBeTruthy();
    expect(p.textContent).toContain('A description');
  });

  it('should forward testId to data-testid attribute when provided', () => {
    fixture.componentRef.setInput('testId', 'my-card');
    fixture.detectChanges();
    expect(cardEl().getAttribute('data-testid')).toBe('my-card');
  });

  it('should have no data-testid attribute when testId is null', () => {
    // testId defaults to null
    fixture.detectChanges();
    expect(cardEl().getAttribute('data-testid')).toBeNull();
  });

  it('should apply p-0 class when padding is none', () => {
    fixture.componentRef.setInput('padding', 'none');
    fixture.detectChanges();
    expect(cardEl().className).toContain('p-0');
  });

  it('should apply p-6 class when padding is lg', () => {
    fixture.componentRef.setInput('padding', 'lg');
    fixture.detectChanges();
    expect(cardEl().className).toContain('p-6');
  });

  it('should apply p-4 class when padding is md', () => {
    fixture.componentRef.setInput('padding', 'md');
    fixture.detectChanges();
    expect(cardEl().className).toContain('p-4');
  });

  it('should apply rounded-lg when padding is lg', () => {
    fixture.componentRef.setInput('padding', 'lg');
    fixture.detectChanges();
    expect(cardEl().className).toContain('rounded-lg');
  });

  it('should apply rounded-md when padding is md', () => {
    fixture.componentRef.setInput('padding', 'md');
    fixture.detectChanges();
    expect(cardEl().className).toContain('rounded-md');
  });

  it('should include hover classes when hoverable is true', () => {
    fixture.componentRef.setInput('hoverable', true);
    fixture.detectChanges();
    expect(cardEl().className).toContain('hover:border-border-strong');
    expect(cardEl().className).toContain('hover:bg-elevated');
  });

  it('should not include hover classes when hoverable is false', () => {
    fixture.componentRef.setInput('hoverable', false);
    fixture.detectChanges();
    expect(cardEl().className).not.toContain('hover:border-border-strong');
  });

  it('should always include bg-panel base class', () => {
    fixture.detectChanges();
    expect(cardEl().className).toContain('bg-panel');
  });

  describe('content projection', () => {
    let hostFixture: ComponentFixture<ProjectionHostComponent>;

    beforeEach(async () => {
      hostFixture = TestBed.createComponent(ProjectionHostComponent);
      hostFixture.detectChanges();
    });

    it('should project body content into the default slot', () => {
      const body = hostFixture.nativeElement.querySelector(
        '[data-testid="card-body"]',
      );
      expect(body).toBeTruthy();
      expect(body.textContent).toContain('Body content');
    });

    it('should project card-actions content when title is shown', () => {
      const actionBtn = hostFixture.nativeElement.querySelector(
        '[data-testid="card-action-btn"]',
      );
      expect(actionBtn).toBeTruthy();
    });

    it('should project card-footer content', () => {
      const footer = hostFixture.nativeElement.querySelector(
        '[data-testid="card-footer-slot"]',
      );
      expect(footer).toBeTruthy();
      expect(footer.textContent).toContain('Footer');
    });

    it('should forward testId via attribute binding in projection host', () => {
      const cardDiv = hostFixture.nativeElement.querySelector(
        '[data-testid="proj-card"]',
      );
      expect(cardDiv).toBeTruthy();
    });
  });
});
