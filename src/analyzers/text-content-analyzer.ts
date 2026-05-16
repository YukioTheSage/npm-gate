export interface InvisibleUnicodeMatch {
  label: string;
  codePoint: string;
}

const invisibleUnicodePatterns: Array<[string, RegExp]> = [
  ['bidirectional control character', /[\u202A-\u202E\u2066-\u2069]/u],
  ['zero-width character', /[\u200B-\u200D\u2060\uFEFF]/u],
  ['variation selector', /[\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]/u]
];

export function firstInvisibleUnicodeMatch(text: string): InvisibleUnicodeMatch | undefined {
  for (const [label, pattern] of invisibleUnicodePatterns) {
    const match = pattern.exec(text);
    if (!match?.[0]) continue;
    return {
      label,
      codePoint: `U+${match[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`
    };
  }
  return undefined;
}
