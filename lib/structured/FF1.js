/* eslint-disable no-bitwise */

const bigInt = require('big-integer');
const FFX = require('./FFX');
const arrayUtil = require('./arrayUtil');
const { bigint_get_str, bigint_set_str } = require('./Bn');

function bytesToInteger(hex, d) {
  let pow = bigInt.one;
  let result = bigInt.zero;
  for (let i = 1; i <= d; i++) {
    result = result.add(pow.multiply(hex[d - i]));
    pow = pow.multiply(256);
  }
  return result;
}

class FF1 extends FFX {
  constructor(key, twk, twkmin, twkmax, radix, custom_radix_str) {
    if (custom_radix_str) {
      radix = custom_radix_str.length;
    }
    super(key, twk, bigInt.one.shiftLeft(32), twkmin, twkmax, radix, custom_radix_str);
  }

  /*
   * The comments below reference the steps of the algorithm described here:
   *
   * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
   */
  cipher(X, twk, encrypt) {
    /* Step 1 */
    const n = X.length;
    // Let u = ⎣n/2⎦; v = n – u.
    const u = Math.floor(parseInt(n / 2, 10));
    const v = n - u;

    /* Step 2 */
    let A = null;
    let B = null;
    // Let A = X[1..u]; B = X[u + 1..n].
    if (encrypt) {
      A = X.substring(0, u);
      B = X.substring(u);
    } else {
      B = X.substring(0, u);
      A = X.substring(u);
    }
    /* Step 3 */
    // 3.	 Let b = ⎡ ⎡v⋅LOG(radix)⎤/8⎤.
    const x = (parseInt(Math.ceil((Math.log(this.radix) / Math.log(2)) * v), 10) + 7);
    const b = parseInt(x / 8, 10);

    /* Step 4 */
    // 4.	 Let d = 4⎡b/4⎤ + 4.
    const d = 4 * (parseInt((b + 3) / 4, 10)) + 4;
    const p = 16;
    const r = (parseInt((d + 15) / 16, 10)) * 16;
    const R = new Uint8Array(r).fill(null);
    let q = 0;
    /* use default tweak if none is supplied */
    if (!twk) {
      twk = this.twk;
    }
    /* check text and tweak lengths */
    if (n < this.txtmin || n > this.txtmax) {
      throw new Error('invalid input length');
    } else if (twk.length < this.twkmin || (this.twkmax > 0 && twk.length > this.twkmax)) {
      throw new Error('invalid tweak length');
    }
    /* the number of bytes in Q */
    q = (parseInt((twk.length + b + 1 + 15) / 16, 10)) * 16;
    /*
     * P and Q need to be adjacent in memory for the
     * purposes of encryption
     */
    const PQ = new Uint8Array(p + q).fill(null);
    PQ[0] = 1;
    PQ[1] = 2;
    PQ[2] = 1;
    PQ[3] = this.radix >> 16;
    PQ[4] = this.radix >> 8;
    PQ[5] = this.radix >> 0;
    PQ[6] = 10;
    PQ[7] = u;
    PQ[8] = n >> 24;
    PQ[9] = n >> 16;
    PQ[10] = n >> 8;
    PQ[11] = n >> 0;
    PQ[12] = twk.length >> 24;
    PQ[13] = twk.length >> 16;
    PQ[14] = twk.length >> 8;
    PQ[15] = twk.length >> 0;
    /* Step 6i, the static parts */
    arrayUtil.arrayCopy(twk, 0, PQ, p, twk.length);
    /* remainder of Q already initialized to 0 */
    for (let i = 0; i < 10; i++) {
      /* Step 6v */
      const m = ((i + !!encrypt) % 2) ? u : v;

      const radixPow = bigInt(this.radix).pow(m);
      let c = null;
      let y = null;
      let numb;
      /* Step 6i, the non-static parts */
      PQ[PQ.length - b - 1] = encrypt ? i : (9 - i);
      /*
      * convert the numeral string B to an integer and
      * export that integer as a byte array into Q
      */
      c = bigint_set_str(B, this.custom_radix_str, this.radix);// bigInt(B, this.radix);
      numb = this.BigIntToByteArray(c);
      if (numb[0] === 0 && numb.length > 1) {
        /*
         * Per the Java documentation, BigInteger.toByteArray always
         * returns enough bytes to contain a sign bit. For the purposes
         * of this function all numbers are unsigned; however, when the
         * most-significant bit is set in a number, the Java library
         * returns an extra most-significant byte that is set to 0.
         * That byte must be removed for the cipher to work correctly.
         */
        numb = arrayUtil.copyOfRange(numb, 1, numb.length);
      }
      if (b <= numb.length) {
        arrayUtil.arrayCopy(numb, 0, PQ, PQ.length - b, b);
      } else {
        /* pad on the left with zeros */
        PQ.fill(0, PQ.length - b, PQ.length - numb.length);
        arrayUtil.arrayCopy(numb, 0, PQ, PQ.length - numb.length, numb.length);
      }
      /* Step 6ii */
      this.prf(R, 0, PQ, 0, PQ.length);
      /*
       * Step 6iii
       * if r is greater than 16, fill the subsequent blocks
       * with the result of ciph(R ^ 1), ciph(R ^ 2), ...
       */
      // Let S be the first d bytes of the following string of ⎡d/16⎤ blocks:
      // R || CIPHK (R ⊕ [1]16) || CIPHK (R ⊕ [2]16) … CIPHK (R ⊕ [⎡d/16⎤–1]16).
      let l;
      for (let j = 1; j < parseInt(r / 16, 10); j++) {
        l = j * 16;
        R.fill(0, l, l + 12);
        R[l + 12] = j >> 24;
        R[l + 13] = j >> 16;
        R[l + 14] = j >> 8;
        R[l + 15] = j >> 0;

        this.xor(R, l, R, 0, R, l, 16);
        this.ciph(R, l, R, l);
      }
      /*
       * Step 6vi
       * calculate A +/- y mod radix**m
       * where y is the number formed by the first d bytes of R
       * * create an integer from the first @d bytes in @R
       */
      // vi.	 Let c = (NUM radix (A)+y) mod radix m .
      c = bigint_set_str(A, this.custom_radix_str, this.radix);
      y = bytesToInteger(R, d);
      y = y.mod(radixPow);
      // vii.	 Let C = STR m	radix(c).
      if (encrypt) {
        c = c.add(y);
      } else {
        c = c.subtract(y);
      }

      c = c.mod(radixPow);
      // the algorithm appears to need a number between 0 and the dominator,
      // this if statement prevents result to be negative.
      if (c < 0) {
        c = c.add(radixPow);
      }
      const C = this.str(m, this.radix, c);
      /* Step 6viii */
      A = B;
      B = C;
    }
    /* Step 7 */
    return encrypt ? (A + B) : (B + A);
  }
}
// /* make available to other modules */
module.exports = { FF1 };
