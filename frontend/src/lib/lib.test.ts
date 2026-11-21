import { describe, expect, it } from 'vitest';
import { ExportParseError, parseExportText } from './exportParser';
import { computeMutuals, computeStats, diffSnapshots, toCsv } from './mutuals';

const entry = (name: string, via: 'value' | 'title' | 'href' = 'value') => ({
  title: via === 'title' ? name : '',
  media_list_data: [],
  string_list_data: [{ href: `https://www.instagram.com/${name}`, value: via === 'value' ? name : '', timestamp: 1 }],
});

describe('parseExportText', () => {
  it('reads followers (array root) and following (object root)', () => {
    expect(parseExportText(JSON.stringify([entry('Alice'), entry('bob_1')])).usernames.sort()).toEqual(['alice', 'bob_1']);
    expect(parseExportText(JSON.stringify({ relationships_following: [entry('carol', 'title')] })).usernames).toEqual(['carol']);
    expect(parseExportText(JSON.stringify([entry('dave', 'href')])).usernames).toEqual(['dave']);
  });
  it('de-duplicates and counts skipped invalid entries', () => {
    const r = parseExportText(JSON.stringify([entry('a'), entry('a'), { title: '<script>alert(1)</script>', string_list_data: [] }]));
    expect(r.usernames).toEqual(['a']);
    expect(r.skipped).toBe(1);
  });
  it('never emits a value outside the username allow-list', () => {
    const evil = [{ title: '"><img src=x onerror=1>', string_list_data: [{ value: 'a b', href: 'https://evil.example/x' }] }, entry('ok')];
    expect(parseExportText(JSON.stringify(evil)).usernames).toEqual(['ok']);
  });
  it('rejects non-JSON, wrong shapes and all-invalid files', () => {
    expect(() => parseExportText('<html>')).toThrowError(ExportParseError);
    expect(() => parseExportText('{"a":1}')).toThrowError(ExportParseError);
    expect(() => parseExportText(JSON.stringify([{ title: '!!!' }]))).toThrowError(ExportParseError);
  });
  it('rejects oversized input', () => {
    expect(() => parseExportText('x'.repeat(26 * 1024 * 1024))).toThrowError(/25 MB/);
  });
});

describe('computeMutuals', () => {
  it('splits into mutuals, not-following-back and fans', () => {
    const r = computeMutuals(['a', 'b', 'c'], ['b', 'c', 'd']);
    expect(r).toEqual({ mutuals: ['b', 'c'], notFollowingBack: ['d'], fans: ['a'] });
  });
  it('handles empty lists', () => {
    expect(computeMutuals([], [])).toEqual({ mutuals: [], notFollowingBack: [], fans: [] });
  });
});

describe('toCsv', () => {
  it('emits a header and one username per row', () => {
    expect(toCsv(['a', 'b'])).toBe('username\r\na\r\nb\r\n');
  });
  it('blanks anything that could start a formula', () => {
    expect(toCsv(['=cmd'])).toBe('username\r\n\r\n');
  });
});

describe('diffSnapshots', () => {
  it('finds new and lost followers', () => {
    expect(diffSnapshots(['a', 'b', 'c'], ['b', 'c', 'd'])).toEqual({ newFollowers: ['d'], lostFollowers: ['a'] });
  });
  it('reports nothing when snapshots match', () => {
    expect(diffSnapshots(['a'], ['a'])).toEqual({ newFollowers: [], lostFollowers: [] });
  });
});

describe('computeStats', () => {
  it('computes rates and ratio', () => {
    expect(computeStats(['a', 'b', 'c', 'd'], ['a', 'b'], 2)).toEqual({ followBackRate: 100, mutualShareOfFollowers: 50, ratio: 2 });
  });
  it('avoids dividing by zero', () => {
    expect(computeStats([], [], 0)).toEqual({ followBackRate: null, mutualShareOfFollowers: null, ratio: null });
  });
});
