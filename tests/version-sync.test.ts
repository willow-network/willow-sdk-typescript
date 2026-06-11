import { VERSION } from '../src';
import pkg from '../package.json';

/**
 * The runtime `VERSION` constant is hand-maintained (it can't import
 * package.json into the published bundle without bloating it), so guard it
 * with a test: a version bump that forgets either side fails here.
 */
describe('VERSION', () => {
  it('matches the version in package.json', () => {
    expect(VERSION).toBe(pkg.version);
  });
});
