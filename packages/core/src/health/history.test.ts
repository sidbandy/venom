import { afterEach, describe, expect, it } from 'vitest';
import { ScoreHistoryStore } from './history';

let store: ScoreHistoryStore;
afterEach(() => store?.close());

describe('ScoreHistoryStore', () => {
  it('records runs and returns them newest first', () => {
    store = new ScoreHistoryStore(':memory:');
    store.record({
      timestamp: '2026-07-01T00:00:00Z',
      score: 72,
      grade: 'C',
      cveCount: 5,
      secretCount: 0,
    });
    store.record({
      timestamp: '2026-07-05T00:00:00Z',
      score: 68,
      grade: 'D',
      cveCount: 7,
      secretCount: 1,
    });
    store.record({
      timestamp: '2026-07-11T00:00:00Z',
      score: 74,
      grade: 'C',
      cveCount: 4,
      secretCount: 0,
    });

    const recent = store.recent();
    expect(recent).toHaveLength(3);
    expect(recent.map((r) => r.score)).toEqual([74, 68, 72]); // newest first
    expect(recent[0]).toMatchObject({ grade: 'C', cveCount: 4, secretCount: 0 });
  });

  it('honors the limit', () => {
    store = new ScoreHistoryStore(':memory:');
    for (let i = 0; i < 5; i++) {
      store.record({
        timestamp: `2026-07-0${i}T00:00:00Z`,
        score: 70 + i,
        grade: 'C',
        cveCount: 0,
        secretCount: 0,
      });
    }
    expect(store.recent(2)).toHaveLength(2);
  });
});
