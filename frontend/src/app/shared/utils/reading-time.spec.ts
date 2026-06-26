import { estimateReadingTime } from './reading-time';

describe('estimateReadingTime', () => {
  it('should return 0 for empty content', () => {
    expect(estimateReadingTime('')).toBe(0);
    expect(estimateReadingTime('   \n\t ')).toBe(0);
  });

  it('should return at least 1 minute for any non-empty content', () => {
    expect(estimateReadingTime('hello world')).toBe(1);
    expect(estimateReadingTime('字')).toBe(1);
  });

  it('should count latin words at 220 wpm, rounding up', () => {
    expect(estimateReadingTime(Array(220).fill('word').join(' '))).toBe(1);
    expect(estimateReadingTime(Array(221).fill('word').join(' '))).toBe(2);
    expect(estimateReadingTime(Array(440).fill('word').join(' '))).toBe(2);
  });

  it('should count CJK characters at 400 cpm, rounding up', () => {
    expect(estimateReadingTime('字'.repeat(400))).toBe(1);
    expect(estimateReadingTime('字'.repeat(401))).toBe(2);
    expect(estimateReadingTime('字'.repeat(800))).toBe(2);
  });

  it('should add CJK and latin contributions for mixed content', () => {
    // 400 CJK (1.0 min) + 220 latin words (1.0 min) = ceil(2.0) = 2.
    const mixed = '字'.repeat(400) + ' ' + Array(220).fill('word').join(' ');
    expect(estimateReadingTime(mixed)).toBe(2);
  });
});
