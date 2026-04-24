import { AnimationTriggerMetadata } from '@angular/animations';
import { fadeInUp, staggerFadeIn, slideDown } from './fade-in.animation';

describe('fade-in animations', () => {
  it('should export fadeInUp animation trigger', () => {
    expect(fadeInUp).toBeDefined();
    expect((fadeInUp as AnimationTriggerMetadata).name).toBe('fadeInUp');
  });

  it('should export slideDown animation trigger', () => {
    expect(slideDown).toBeDefined();
    expect((slideDown as AnimationTriggerMetadata).name).toBe('slideDown');
  });

  it('should export staggerFadeIn animation trigger', () => {
    expect(staggerFadeIn).toBeDefined();
    expect((staggerFadeIn as AnimationTriggerMetadata).name).toBe(
      'staggerFadeIn',
    );
  });
});
