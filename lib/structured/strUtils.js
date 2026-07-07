

const verbose = false
/**
     * Inserts a character at a position in a String.
     *
     * Convenience function returns String with inserted char
     * at an index position.
     *
     * @param str the original String
     * @param ch the character to insert
     * @param position the index position where to insert the ch
     *
     * @return    the new String containing the inserted ch
     */
function insertChar(str, ch, position) {
  return str.substring(0, position) + ch + str.substr(position);
}

function padLeft(c, length, s) {
  if (s.length < length) {
    return c.repeat(length - s.length) + s;
  }
  return s;
}

function isNullOrEmpty(str) {
  return str == null || str.trim() === '';
}

function trimLeftPad(str, trimChar) {
  if (str == null || str.length === 0) return str;

  let idx = -1;

  if (str.charAt(0) === trimChar) {
    idx = 1;
    while (idx < str.length && str.charAt(idx) === trimChar) {
      idx++;
    }
  }

  return idx >= 0 ? str.substring(idx) : str;
}

// Base32 encoder (RFC 4648, no padding)
function base32Encode(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  let bits = 0;
  let value = 0;

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(value >> bits) & 0x1f];
    }
  }

  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 0x1f];
  }

  // ADD THIS LINE FOR COMPATIBILITY WITH JAVA DEFAULT:
  while (result.length % 8 !== 0) {
    result += '=';
  }
  return result;
}

// Base32 decoder (RFC 4648, handles optional padding)
function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  // Normalize: uppercase and strip padding
  const str = input.toUpperCase().replace(/=+$/, '');

  const bytes = [];
  let bits = 0;
  let value = 0;

  for (const char of str) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base32 character: '${char}'`);

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }

  return Buffer.from(bytes).toString('UTF8');
}

function formatToTemplate(input, template, passthroughCharacters) {
  const passthroughSet = new Set(passthroughCharacters);
  const result = template.split('');
  let j = 0;

  for (let i = 0; i < result.length; i++) {
    if (passthroughSet.has(result[i])) {
      continue;
    }

    if (j >= input.length) {
      throw new Error('Input length does not match template');
    }

    result[i] = input[j++];
  }

  if (j !== input.length) {
    throw new Error('Input length does not match template');
  }

  return result.join('');
}

function encodeKeyNumber(str, alphabet, msbEncodingBits, keyNumber) {
  const charBuf = str[0];
  let ct_value = alphabet.indexOf(charBuf);
  if (verbose) { console.log(`encodeKeyNumber ct_value: ${ct_value} alphabet: ${alphabet}`) }
  if (verbose) { console.log(`encodeKeyNumber keyNumber << msbEncodingBits: ${(keyNumber << Number(msbEncodingBits))}`) }
  ct_value = ct_value + (keyNumber << Number(msbEncodingBits));
  const ch = alphabet[ct_value];
  if (verbose) { console.log(`encodeKeyNumber ct_value: ${ct_value} keyNumber: ${keyNumber} msbEncodingBits: ${msbEncodingBits} ch: ${ch}`) }
  if (verbose) { console.log(`encodeKeyNumber str: "${str}"`) }
  str = str.substring(0, 0) + ch + str.substring(1);
  return str;
}

function decodeKeyNumber(str, alphabet, msbEncodingBits) {

  const encoded_value = alphabet.indexOf(str[0]);
  if (verbose) { console.log(`decodeKeyNumber alphabet: ${alphabet} msbEncodingBits: ${msbEncodingBits} msbEncodingBits: ${Number(msbEncodingBits)}`) }
  const keyNumber = (encoded_value >> Number(msbEncodingBits));
  if (verbose) { console.log(`decodeKeyNumber encoded_value: ${encoded_value} idx: ${encoded_value - (keyNumber << Number(msbEncodingBits))}`) }
  const ch = alphabet[encoded_value - (keyNumber << Number(msbEncodingBits))];
  if (verbose) { console.log(`decodeKeyNumber str: ${str} keyNumber: ${keyNumber} encoded_value: ${encoded_value} msbEncodingBits: ${msbEncodingBits} ch: ${ch}`) }
  return {
    str: ch + str.slice(1),
    key_number: keyNumber
  };
}


module.exports = {
  insertChar,
  padLeft,
  isNullOrEmpty,
  trimLeftPad,
  base32Encode,
  base32Decode,
  formatToTemplate,
  encodeKeyNumber,
  decodeKeyNumber
};
