import { G1Point, G2Point, initCurves, Transcript } from '../src';
import { modQ, Q } from '../src/crypto/field';

beforeAll(async () => {
  await initCurves();
});

describe('Transcript', () => {
  it('identical appends → identical challenge (deterministic)', () => {
    const a = new Transcript('L');
    const b = new Transcript('L');
    a.append('x', new Uint8Array([1, 2, 3]));
    b.append('x', new Uint8Array([1, 2, 3]));
    expect(a.challenge('c')).toBe(b.challenge('c'));
  });

  it('different labels → different challenge', () => {
    const a = new Transcript('A');
    const b = new Transcript('B');
    expect(a.challenge('c')).not.toBe(b.challenge('c'));
  });

  it('different tags on the same value → different challenge', () => {
    const a = new Transcript('L');
    const b = new Transcript('L');
    a.append('tag1', new Uint8Array([1]));
    b.append('tag2', new Uint8Array([1]));
    expect(a.challenge('c')).not.toBe(b.challenge('c'));
  });

  it('challenge tag contributes to the scalar', () => {
    const t = new Transcript('L');
    const copy = new Transcript('L');
    expect(t.challenge('alpha')).not.toBe(copy.challenge('beta'));
  });

  it('challenge is folded back: second challenge depends on first', () => {
    const t1 = new Transcript('L');
    const t2 = new Transcript('L');
    t1.challenge('first');
    // t2 does not draw "first" — so its "second" challenge must differ.
    expect(t1.challenge('second')).not.toBe(t2.challenge('second'));
  });

  it('appendPoint binds the compressed encoding', () => {
    const g = G2Point.generator();
    const h = G1Point.generator();
    const a = new Transcript('L');
    const b = new Transcript('L');
    a.appendPoint('g2', g);
    b.appendPoint('g2', g);
    expect(a.challenge('c')).toBe(b.challenge('c'));

    const mixed = new Transcript('L');
    mixed.appendPoint('g2', g);
    const other = new Transcript('L');
    other.appendPoint('g1', h);
    expect(mixed.challenge('c')).not.toBe(other.challenge('c'));
  });

  it('appendScalar produces in-range challenges and is order-sensitive', () => {
    const a = new Transcript('L');
    const b = new Transcript('L');
    a.appendScalar('x', 1n);
    a.appendScalar('y', 2n);
    b.appendScalar('y', 2n);
    b.appendScalar('x', 1n);
    // Tags are distinct, order is flipped → different challenge.
    expect(a.challenge('c')).not.toBe(b.challenge('c'));
    const c = a.challenge('d'); // c is a fresh challenge
    expect(c).toBeGreaterThanOrEqual(0n);
    expect(c).toBeLessThan(Q);
  });

  it('length-prefix makes concatenation injective (no collisions via splitting)', () => {
    const ab = new Transcript('L');
    ab.append('t', new Uint8Array([1, 2, 3, 4]));
    const split = new Transcript('L');
    split.append('t', new Uint8Array([1, 2]));
    split.append('t', new Uint8Array([3, 4]));
    expect(ab.challenge('c')).not.toBe(split.challenge('c'));
  });

  it('rejects scalar out of [0, Q) on appendScalar', () => {
    const t = new Transcript('L');
    expect(() => t.appendScalar('bad', Q)).toThrow(/out of range/);
    expect(() => t.appendScalar('bad', -1n)).toThrow(/out of range/);
    expect(() => t.appendScalar('ok', modQ(-1n))).not.toThrow();
  });

  // `preimage()` is what signature schemes bind (ATTESTATION_V1 signs
  // keccak256 of it) rather than deriving a Fiat–Shamir challenge. Its exact
  // layout is therefore an interop contract with the Python implementation;
  // the geg attestation vectors are the cross-language lock, and these are the
  // direct structural checks.
  describe('preimage()', () => {
    it('is the label followed by length-framed (tag, value) pairs', () => {
      const t = new Transcript('AB');
      t.append('xy', new Uint8Array([0xde, 0xad]));
      expect(Buffer.from(t.preimage()).toString('hex')).toBe(
        [
          '4142', //           label "AB", raw, no length prefix
          '00000002', //       u32BE len("xy")
          '7879', //           "xy"
          '00000002', //       u32BE len(value)
          'dead' //            value
        ].join('')
      );
    });

    it('bare transcript preimage is just the label', () => {
      expect(Buffer.from(new Transcript('L').preimage()).toString('hex')).toBe(
        '4c'
      );
    });

    it('appendScalar contributes a 32-byte big-endian value', () => {
      const t = new Transcript('');
      t.appendScalar('s', 1n);
      expect(Buffer.from(t.preimage()).toString('hex')).toBe(
        `00000001` + `73` + `00000020${'00'.repeat(31)}01`
      );
    });

    it('is a pure read — calling it does not disturb challenges', () => {
      const a = new Transcript('L');
      const b = new Transcript('L');
      a.append('x', new Uint8Array([7]));
      b.append('x', new Uint8Array([7]));
      // Read a's preimage twice before drawing; b never reads.
      expect(Buffer.from(a.preimage())).toEqual(Buffer.from(a.preimage()));
      expect(a.challenge('c')).toBe(b.challenge('c'));
    });

    it('grows by the folded challenge after challenge() (fold-back is visible)', () => {
      const t = new Transcript('L');
      const before = t.preimage().length;
      t.challenge('c');
      // challenge() folds `appendScalar(tag + ':chal', e)` back in:
      // u32BE(len("c:chal")) + "c:chal" + u32BE(32) + 32 bytes
      expect(t.preimage().length).toBe(before + 4 + 6 + 4 + 32);
    });
  });
});
