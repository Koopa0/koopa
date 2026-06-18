import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { AvatarGroupComponent } from './avatar-group.component';
import { AvatarComponent } from '../avatar/avatar.component';

@Component({
  standalone: true,
  imports: [AvatarGroupComponent, AvatarComponent],
  template: `
    <app-avatar-group [overflow]="overflow()" [testId]="testId()">
      <app-avatar initials="AA" />
      <app-avatar initials="BB" />
    </app-avatar-group>
  `,
})
class AvatarGroupHostComponent {
  readonly overflow = signal(0);
  readonly testId = signal<string | null>(null);
}

describe('AvatarGroupComponent', () => {
  let fixture: ComponentFixture<AvatarGroupHostComponent>;
  let host: AvatarGroupHostComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AvatarGroupHostComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(AvatarGroupHostComponent);
    host = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(host).toBeTruthy();
  });

  describe('projected avatars', () => {
    it('should render projected avatar children', () => {
      const avatars = fixture.nativeElement.querySelectorAll('app-avatar');
      expect(avatars.length).toBe(2);
    });
  });

  describe('overflow bubble', () => {
    it('should not render overflow bubble when overflow is 0', async () => {
      host.overflow.set(0);
      await fixture.whenStable();

      const bubble = fixture.nativeElement.querySelector(
        '[data-testid$="-overflow"]',
      );
      expect(bubble).toBeNull();
    });

    it('should render overflow bubble with correct count when overflow is positive', async () => {
      host.overflow.set(3);
      await fixture.whenStable();

      const bubbles = fixture.nativeElement.querySelectorAll('span');
      const overflowBubble = Array.from(bubbles).find((el) =>
        (el as HTMLElement).textContent?.trim().startsWith('+'),
      ) as HTMLElement | undefined;
      expect(overflowBubble).toBeTruthy();
      expect(overflowBubble?.textContent?.trim()).toBe('+3');
    });

    it('should update overflow bubble text when overflow input changes', async () => {
      host.overflow.set(5);
      await fixture.whenStable();

      const spansBefore = fixture.nativeElement.querySelectorAll('span');
      const bubbleBefore = Array.from(spansBefore).find((el) =>
        (el as HTMLElement).textContent?.trim().startsWith('+'),
      ) as HTMLElement | undefined;
      expect(bubbleBefore?.textContent?.trim()).toBe('+5');

      host.overflow.set(12);
      await fixture.whenStable();

      const spansAfter = fixture.nativeElement.querySelectorAll('span');
      const bubbleAfter = Array.from(spansAfter).find((el) =>
        (el as HTMLElement).textContent?.trim().startsWith('+'),
      ) as HTMLElement | undefined;
      expect(bubbleAfter?.textContent?.trim()).toBe('+12');
    });

    it('should hide overflow bubble again when overflow changes back to 0', async () => {
      host.overflow.set(4);
      await fixture.whenStable();

      host.overflow.set(0);
      await fixture.whenStable();

      const spans = fixture.nativeElement.querySelectorAll('span');
      const overflowBubble = Array.from(spans).find((el) =>
        (el as HTMLElement).textContent?.trim().startsWith('+'),
      );
      expect(overflowBubble).toBeUndefined();
    });
  });

  describe('testId', () => {
    it('should set data-testid on the container when testId is provided', async () => {
      host.testId.set('team-avatars');
      await fixture.whenStable();

      const container = fixture.nativeElement.querySelector(
        '[data-testid="team-avatars"]',
      );
      expect(container).toBeTruthy();
    });

    it('should set data-testid on the overflow bubble when testId is provided', async () => {
      host.testId.set('team-avatars');
      host.overflow.set(2);
      await fixture.whenStable();

      const overflowEl = fixture.nativeElement.querySelector(
        '[data-testid="team-avatars-overflow"]',
      );
      expect(overflowEl).toBeTruthy();
    });

    it('should not set data-testid on container when testId is null', async () => {
      host.testId.set(null);
      await fixture.whenStable();

      const container = fixture.nativeElement.querySelector('div[data-testid]');
      expect(container).toBeNull();
    });
  });
});
