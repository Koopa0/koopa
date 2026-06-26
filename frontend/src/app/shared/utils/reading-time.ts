/** Latin words read per minute. */
const LATIN_WPM = 220;
/** CJK characters read per minute (no inter-word spaces, so counted per glyph). */
const CJK_CPM = 400;

/** Hiragana/Katakana, CJK Ext-A, CJK Unified, CJK Compat, and Hangul. */
const CJK = /[぀-ヿ㐀-䶿一-鿿豈-﫿가-힯]/g;

/**
 * Estimate reading time in whole minutes from a content body, so the editor
 * never asks the author to fill it in. Mixed scripts are handled: CJK is
 * counted per character (no spaces between words), Latin per whitespace-
 * delimited word. Returns 0 for empty content, otherwise at least 1.
 */
export function estimateReadingTime(body: string): number {
  const cjk = body.match(CJK)?.length ?? 0;
  const latin =
    body.replace(CJK, ' ').match(/[A-Za-z0-9]+(?:['-][A-Za-z0-9]+)*/g)?.length ??
    0;
  if (cjk === 0 && latin === 0) {
    return 0;
  }
  return Math.max(1, Math.ceil(cjk / CJK_CPM + latin / LATIN_WPM));
}
