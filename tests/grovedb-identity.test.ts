import { grovedb as rootGrovedb } from '../src';
import { GroveDBVerificationError as SubGroveDBVerificationError } from '../src/grovedb';

/**
 * The package ships two entry points (root `grovedb` namespace and the
 * `./grovedb` subpath). tsup `splitting: true` emits the grovedb module as a
 * single shared chunk both bundles import, so the error classes must be
 * identity-equal across the two — otherwise `instanceof` silently fails for
 * consumers who catch a root-namespace error against the subpath class (or
 * vice-versa). This guards the source-level identity; the build is checked
 * against the packed tarball separately.
 */
describe('grovedb cross-entry-point class identity', () => {
  it('GroveDBVerificationError is the same class from the root namespace and the subpath', () => {
    expect(rootGrovedb.GroveDBVerificationError).toBe(SubGroveDBVerificationError);
  });

  it('a root-namespace error is instanceof the subpath class and vice-versa', () => {
    const fromRoot = new rootGrovedb.GroveDBVerificationError('boom');
    const fromSub = new SubGroveDBVerificationError('boom');
    expect(fromRoot).toBeInstanceOf(SubGroveDBVerificationError);
    expect(fromSub).toBeInstanceOf(rootGrovedb.GroveDBVerificationError);
  });
});
