/* eslint-disable no-bitwise */

const bigInt = require('big-integer');
const { createCipheriv } = require('crypto');
const errorMessages = require('./errorMessages');
const { arrayCopy } = require('./arrayUtil');
const Bn = require('./Bn');
/*
12/27/21
Check in non-functional initial code skeleton.
How to compile:
node FFX.js
*/

class FFX {
  constructor(key, twk, txtmax, twkmin, twkmax, radix, custom_radix_str) {
    let txtmin = 0;
    this.radix = 0;
    this.txtmin = 0;
    this.txtmax = 0;
    this.twkmin = 0;
    this.twkmax = 0;
    this.twk = [];
    this.custom_radix_str = undefined;

    // this.cipher = null;
    let algorithm;
    /* all 3 key sizes of AES are supported */
    switch (key.length) {
      case 16:
        algorithm = 'aes-128-cbc';
        break;
      case 24:
        algorithm = 'aes-192-cbc';
        break;
      case 32:
        algorithm = 'aes-256-cbc';
        break;
      default:
        throw new Error(`key size error: ${key.length}`);
    }
    /*
     * FF1 supports a radix up to 65536, but the
     * implementation becomes increasingly difficult and
     * less useful in practice after the limits below.
     */
    if (radix < 2 || radix > 36) {
      // throw new Error('invalid radix');
    }

    /*
     * for ff1 : radix**minlen >= 1000000
     *
     * therefore:
     *   minlen = ceil(log_radix(1000000))
     *          = ceil(log_10(1000000) / log_10(radix))
     *          = ceil(6 / log_10(radix))
     */
    txtmin = parseInt(Math.ceil(6.0 / Math.log10(radix), 10), 10);
    if (txtmin < 2 || txtmin > txtmax) {
      throw new Error('minimum text length out of range');
    }

    /* the default tweak must be specified */
    if (!twk) {
      throw new Error('invalid tweak');
    }
    /* check tweak lengths */
    if (twkmin > twkmax || twk.length < twkmin || (twkmax > 0 && twk.length > twkmax)) {
      throw new Error('invalid tweak length');
    }

    const iv = Buffer.alloc(16, 0);
    const keyArrayBuffer = new Buffer.from(key);
    this.algorithm = algorithm;
    this.keyArrayBuffer = keyArrayBuffer;
    this.iv = iv;
    this.Cipher = createCipheriv(algorithm, keyArrayBuffer, iv);
    this.Cipher.setAutoPadding(false);

    this.radix = radix;
    this.txtmin = txtmin;
    this.txtmax = txtmax;
    this.twkmin = twkmin;
    this.twkmax = twkmax;
    this.twk = [...twk];
    this.custom_radix_str = custom_radix_str;
  }

  /*
   * perform an aes-cbc encryption (with an IV of 0) of @src, storing
   * the last block of output into @dst. The number of bytes in @src
   * must be a multiple of 16. @dst and @src may point to the same
   * location but may not overlap, otherwise. @dst must point to a
   * location at least 16 bytes long
   */
  prf(dst, doff, src, soff, len) {
    const blksz = 16; // Should be something like this.Cipher.getBlockSize or getCiherInfo.block size
    if ((src.length - soff) % blksz !== 0) {
      throw new Error('invalid source length');
    }
    let tempResult;
    for (let i = 0; i < len && i < src.length - soff; i += blksz) {
      const temp = new Uint8Array(blksz);
      arrayCopy(src, soff + i, temp, 0, blksz);
      tempResult = this.Cipher.update(temp);
    }
    this.Cipher.final();

    for (let j = 0; j < tempResult.length; j++) {
      dst[j + doff] = tempResult[j];
    }
    // reset Cipher
    this.Cipher = createCipheriv(this.algorithm, this.keyArrayBuffer, this.iv);
    this.Cipher.setAutoPadding(false);
  }

  /*
   * perform an aes-ecb encryption of @src. @src and @dst must each be
   * 16 bytes long, starting from the respective offsets. @src and @dst
   * may point to the same location or otherwise overlap
   */
  ciphh(dst, doff, src, soff) {
    this.prf(dst, doff, src, soff, 16);
  }

  /*
   * a convenience version of the ciph function that returns its
   * output as a separate byte array
   */
  ciph(dst, doff, src, off) {
    this.prf(dst, doff, src, off, 16);
  }

  /*
   * convenience function that returns the reversed sequence
   * of bytes as a new byte array
   */
  rev(src) {
    const dst = [...src];
    return dst.reverse();
  }

  /*
   * reverse the characters in a string
  */

  revStr(str) {
    return [...str].reverse().join('');
  }

  /*
   * Perform an exclusive-or of the corresponding bytes
   * in two byte arrays
   */
  xor(d, doff, s1, s1off, s2, s2off, len) {
    for (let i = 0; i < len; i++) {
      d[doff + i] = s1[s1off + i] ^ s2[s2off + i];
    }
  }

  /*
   * convert a big integer to a string under the radix @r with
   * length @m. If the string is longer than @m, the function fails.
   * if the string is shorter that @m, it is zero-padded to the left
  i: type bigInt
  r: int Radix
  m: length
  */

  str(m, r, i) {
    if (!this.custom_radix_str) {
      const s = i.toString(r);
      if (s.length > m) {
        throw new Error(errorMessages.StringExceeds);
      } else if (s.length < m) {
        return s.padStart(m, '0'); // TODO - This may not be safe if custom_radix_str[0] is not the '0' character
      }
      return s;
    }
    const s = Bn.bigint_get_str(this.custom_radix_str, i);
    if (s.length > m) {
      throw new Error(errorMessages.StringExceeds);
    } else if (s.length < m) {
      return s.padStart(m, this.custom_radix_str[0]);
    }
    return s;
  }

  /**
   * Encrypt a string, returning a cipher text using the same alphabet.
   *
   * The key, tweak parameters, and radix were all already set
   * by the initialization of the object.
   *
   * @param X   the plain text to be encrypted
   * @param twk the tweak used to perturb the encryption
   *
   * @return    the encryption of the plain text, the cipher text
   */
  encrypt(X, twk) {
    return this.cipher(X, twk, true);
  }

  /**
   * Decrypt a string, returning the plain text.
   *
   * The key, tweak parameters, and radix were all already set
   * by the initialization of the object.
   *
   * @param X   the cipher text to be decrypted
   * @param twk the tweak used to perturb the encryption
   *
   * @return    the decryption of the cipher text, the plain text
   */
  decrypter(X, twk) {
    return this.cipher(X, twk, false);
  }

  /**
   * Decrypt a string, returning the plain text.
   *
   * The key, tweak parameters, and radix were all already set
   * by the initialization of the object.
   *
   * @param X   the cipher text to be decrypted
   *
   * @return    the decryption of the cipher text, the plain text
   */
  decrypt(X) {
    return this.decrypter(X, null);
  }

  BigIntToByteArray(bn) {
    let hex = bn.toString(16);
    if (hex.length % 2) {
      hex = `0${hex}`;
    }
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);

    let i = 0;
    let j = 0;
    while (i < len) {
      u8[i] = parseInt(`${hex[j]}${hex[j + 1]}`, 16);
      i += 1;
      j += 2;
    }
    return u8;
  }

  ByteArrayToBigInt(buf) {
    const hex = [];
    const u8 = this.Uint8Array.from(buf);

    u8.forEach((i) => {
      let h = i.toString(16);
      if (h.length % 2) { h = `0${h}`; }
      hex.push(h);
    });
    return bigInt(`0x${hex.join('')}`);
  }
}

module.exports = FFX;
