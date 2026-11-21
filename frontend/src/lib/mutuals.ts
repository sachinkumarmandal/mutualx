export interface MutualsResult {
  mutuals: string[];
  notFollowingBack: string[]; // you follow them, they don't follow you
  fans: string[]; // they follow you, you don't follow them
}

const sort = (xs: string[]) => [...xs].sort((a, b) => a.localeCompare(b));

export function computeMutuals(followers: string[], following: string[]): MutualsResult {
  const fSet = new Set(followers);
  const gSet = new Set(following);
  return {
    mutuals: sort(following.filter((u) => fSet.has(u))),
    notFollowingBack: sort(following.filter((u) => !fSet.has(u))),
    fans: sort(followers.filter((u) => !gSet.has(u))),
  };
}

/** Usernames are allow-listed to [a-z0-9._], so cells can never start a spreadsheet formula (= + - @). */
export function toCsv(rows: string[], header = 'username'): string {
  return [header, ...rows.map((r) => (/^[A-Za-z0-9._]+$/.test(r) ? r : ''))].join('\r\n') + '\r\n';
}

export interface Diff {
  newFollowers: string[]; // follow you now, were not in the older export
  lostFollowers: string[]; // were in the older export, not any more
}

/** Compare two follower snapshots (older vs current). */
export function diffSnapshots(older: string[], current: string[]): Diff {
  const o = new Set(older);
  const c = new Set(current);
  return { newFollowers: sort(current.filter((u) => !o.has(u))), lostFollowers: sort(older.filter((u) => !c.has(u))) };
}

export interface Stats {
  followBackRate: number | null; // % of accounts you follow that follow you back
  mutualShareOfFollowers: number | null; // % of your followers you follow back
  ratio: number | null; // followers / following
}

const pct = (a: number, b: number) => (b === 0 ? null : Math.round((a / b) * 1000) / 10);

export function computeStats(followers: string[], following: string[], mutualCount: number): Stats {
  return {
    followBackRate: pct(mutualCount, following.length),
    mutualShareOfFollowers: pct(mutualCount, followers.length),
    ratio: following.length === 0 ? null : Math.round((followers.length / following.length) * 100) / 100,
  };
}
