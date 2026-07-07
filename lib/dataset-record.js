const { DataTypeConfig } = require('./data-type-config')

const verbose = false

class DatasetRecord {

  static PASSTHROUGH_RULES_TYPE = Object.freeze({
    NONE: Symbol('NONE'),
    PASSTHROUGH: Symbol('PASSTHROUGH'),
    PREFIX: Symbol('PREFIX'),
    SUFFIX: Symbol('SUFFIX'),
  });

  constructor(data) {
    this.name = data.name;
    this.dataType = data.data_type;
    this.salt = data.salt;
    this.minInputLength = data.min_input_length;
    this.maxInputLength = data.max_input_length;
    this.inputPadCharacter = data.input_pad_character;
    this.inputEncoding = data.input_encoding;
    this.tweakSource = data.tweak_source;
    this.encryptionAlgorithm = data.encryption_algorithm;
    this.passthroughCharacterSet = data.passthrough;
    this.inputCharacterSet = data.input_character_set;
    this.outputCharacterSet = data.output_character_set;
    this.msbEncodingBits = data.msb_encoding_bits;
    this.tweakMinLen = data.tweak_min_len;
    this.tweakMaxLen = data.tweak_max_len;
    this.tweak = data.tweak;
    this.fpeDefinableType = data.fpe_definable_type;
    this.passthroughRules = data.passthrough_rules;
    this.permissions = {
      decrypt: data.permissions?.decrypt,
      encrypt: data.permissions?.encrypt,
    };

    if (this.inputPadCharacter != null && this.inputPadCharacter.length === 1) {
      this.inputPadCharacter = this.inputPadCharacter[0];
    }

    this.dataTypeConfig = new DataTypeConfig(data.data_type_config);
  }

  canEncrypt() {
    return this.permissions.encrypt === true;
  }

  // Check if decryption is allowed
  canDecrypt() {
    return this.permissions.decrypt === true;
  }

  static parse(input) {
    // const verbose = true
    const csu = "DatasetRecord::parse"
    let rec
    // Allow input to be string or json already
    const data = typeof input === "string" ? JSON.parse(input) : input;
    if (verbose) { console.log(`${csu} data: `, data) }
    // If input is already this class, just use this class
    if (input instanceof DatasetRecord) {
      rec = input
    } else {
      rec = new DatasetRecord(data);
    }

    if (verbose) { console.log(`${csu} rec: `, rec) }
    if (rec.passthroughRules == null) {
      rec.passthroughRules = [];
    }
    rec.passthroughRulesPriority = [];
    rec.passthroughPrefixLength = 0;
    rec.passthroughSuffixLength = 0;

    // Sort passthrough rules by priority ascending
    rec.passthroughRules.sort((a, b) => a.priority - b.priority);

    for (const rule of rec.passthroughRules) {
      if (verbose) console.log(`Type: ${rule.type}     priority: ${rule.priority}`);

      if (rule.type === 'passthrough') {
        rec.passthroughRulesPriority.push(DatasetRecord.PASSTHROUGH_RULES_TYPE.PASSTHROUGH);
        rec.passthroughCharacterSet = String(rule.value);
      } else if (rule.type === 'suffix') {
        rec.passthroughRulesPriority.push(DatasetRecord.PASSTHROUGH_RULES_TYPE.SUFFIX);
        rec.passthroughSuffixLength = Math.trunc(Number(rule.value));
      } else if (rule.type === 'prefix') {
        rec.passthroughRulesPriority.push(DatasetRecord.PASSTHROUGH_RULES_TYPE.PREFIX);
        rec.passthroughPrefixLength = Math.trunc(Number(rule.value));
      }
      // Other rule types are silently ignored
    }

    if (rec.passthroughCharacterSet == null) {
      rec.passthroughCharacterSet = '';
    }
    return rec;
  }


}


module.exports = {
  DatasetRecord
};