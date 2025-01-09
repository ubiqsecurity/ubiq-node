const forge = require('node-forge');
const fetch = require('node-fetch');
const struct = require('python-struct');
const auth = require('./auth');
const Algorithm = require('./algo');
const { BillingEvents } = require('./billingEvents');
const { BillingEventsProcessor } = require('./billingEventsProcessor');
const { UbiqWebServices } = require('./ubiqWebServices');
const { Configuration } = require('./configuration');
const { ubiqCache } = require('./ubiqCache');

const verbose = false;


module.exports = class Decryption {
  // Initialize the decryption module object
  constructor(ubiqCredentials, ubiqConfiguration = null) {
    this.ubiqCredentials = ubiqCredentials
    // The client's public API key (used to identify the client to the server
    this.papi = this.ubiqCredentials.access_key_id;
    // The client's secret API key (used to authenticate HTTP requests)
    this.sapi = this.ubiqCredentials.secret_signing_key;
    // The client's secret RSA encryption key/password (used to decrypt the client's RSA key from the server). This key is not retained by this object.
    this.srsa = this.ubiqCredentials.secret_crypto_access_key;
    // Set host, either the default or the one given by caller
    this.host = this.ubiqCredentials.host;
    this.endpoint_base = `${this.ubiqCredentials.host}/api/v0`;
    this.endpoint = '/api/v0/decryption/key';
    this.decryption_started = false;
    this.decryption_ready = true;

    if (!ubiqConfiguration) {
      this.ubiqConfiguration = new Configuration();
    } else {
      this.ubiqConfiguration = ubiqConfiguration
    }

    this.billing_events = new BillingEvents(this.ubiqConfiguration);
    this.billingEventsProcessor = new BillingEventsProcessor(new UbiqWebServices(this.ubiqCredentials, this.ubiqConfiguration), this.billing_events, this.ubiqConfiguration);

    // If we are NOT caching unstructured keys, then set the ttl to 0
    let ttl = this.ubiqConfiguration.key_caching_ttl_seconds
    if (!this.ubiqConfiguration.key_caching_unstructured) {
      ttl = 0;
    }

    this.cache = new ubiqCache(ttl)
  }

  begin() {
    // Begin the decryption process
    // This interface does not take any cipher text in its arguments
    // in an attempt to maintain an API that corresponds to the
    // encryption object. In doing so, the work that can take place
    // in this function is limited. without any data, there is no
    // way to determine which key is in use or decrypt any data.
    //
    // this function simply throws an error if starting an decryption
    // while one is already in progress, and initializes the internal
    // buffer

    if (!this.decryption_ready) {
      throw new Error('Decryption is not ready');
    }

    if (this.decryption_started) {
      throw new Error('Decryption already in progress');
    }

    // Start the decryption process
    this.decryption_started = true;

    this.data = Buffer.from('');
    return this.data;
  }

  async update(raw_data) {
    // this.update_cipher(data)
    // Decryption of cipher text is performed here
    // Cipher text must be passed to this function in the order in which it was output from the encryption.update function.

    // Each encryption has a header on it that identifies the algorithm
    // used  and an encryption of the data key that was used to encrypt
    // the original plain text. there is no guarantee how much of that
    // data will be passed to this function or how many times this
    // function will be called to process all of the data. to that end,
    // this function buffers data internally, when it is unable to
    // process it.
    //
    // The function buffers data internally until the entire header is
    // received. once the header has been received, the encrypted data
    // key is sent to the server for decryption. after the header has
    // been successfully handled, this function always decrypts all of
    // the data in its internal buffer *except* for however many bytes
    // are specified by the algorithm's tag size. see the end() function
    // for details.
    if (!this.decryption_started) {
      throw new Error('Decryption is not Started');
    }

    // Append the incoming data in the internal data buffer
    const arrData = [this.data, raw_data];
    // Concat the two buffers to form single buffer
    this.data = Buffer.concat(arrData);

    if (typeof this.dec !== 'undefined') {
      return this.update_cipher(this.data);
    } else {
      const struct_length = struct.sizeOf('!BBBBH');
      // Does the buffer contain enough of the header to
      // determine the lengths of the initialization vector
      // and the key?

      if (this.data.length > struct_length) {
        const structed_string = this.data.slice(0, struct_length);

        const struct_buf = new Buffer.from(structed_string, 'binary');

        const arr = struct.unpack('!BBBBH', struct_buf);

        const version = arr[0];
        const flags = arr[1];
        const algorithm_id = arr[2];
        const iv_length = arr[3];
        const key_length = arr[4];

        // verify version is 0 and flags are correct
        if ((version !== 0) || (flags & ~Algorithm.UBIQ_HEADER_V0_FLAG_AAD) !== 0) {
          return;
        }

        // Does the buffer contain the entire header?
        if (this.data.length > struct_length + iv_length + key_length) {
          // Extract the initialization vector
          this.iv = this.data.slice(struct_length, struct_length + iv_length);
          // Extract the encryped key
          const encrypted_key = this.data.slice(struct_length + iv_length, key_length + struct_length + iv_length);

          const encoded_key = forge.util.encode64(encrypted_key.toString('binary'));

          // Shrink the data
          this.data = this.data.slice(key_length + struct_length + iv_length, this.data.length);

          const md = forge.md.sha512.create();
          md.update(encoded_key);

          const client_id = md.digest().data;

          let key = this.cache.get(encoded_key)

          // Key was found in cache - check to see if it needs to be decrypted
          if (typeof key !== 'undefined') {
            this.key = JSON.parse(key)
            if (verbose) console.log(`decrypt:cache hit: `, this.key);
            if (typeof this.key.raw === 'undefined') {
              if (verbose) console.log(`decrypt:cache need to unwrap key:`);
              this.key.raw = await this.unwrapkey()
            }
          }

          // if key does not exist
          if (typeof key === 'undefined' && typeof this.key === 'undefined') {
            if (verbose) console.log(`decrypt:cache miss:`);
            const url = `${this.endpoint_base}/decryption/key`;
            const query = { encrypted_data_key: encoded_key };
            // IDP mode requires passing the idp_cert to the server
            if (this.ubiqCredentials.isIdp()) {
              // Need to check cert before it is used
              await this.ubiqCredentials.renewIdpCertAsync()
              query.payload_cert = this.ubiqCredentials.idp_cert_base64
            }

            const headers = auth.headers(this.papi, this.sapi, this.endpoint, query, this.host, 'post');

            const otherParam = {
              headers,
              body: JSON.stringify(query),
              method: 'POST',
            };

            const response = await fetch(url, otherParam);
            if (response.status === 200) {
              const http_data = await response.json();
              // IDP mode has a local private key, need to override that key since nothing will be returned from server
              if (await this.ubiqCredentials.isIdp()) {
                // Only getting private key here, so cert is still OK
                http_data.encrypted_private_key = this.ubiqCredentials.getEncryptedPrivateKey()
              }
              await this.set_key(http_data, client_id, algorithm_id, encoded_key);
            } else {
              // Throw exception which will be caught and will reject the promise
              throw new Error(`HTTPError Response: Expected 200, got ${response.status}`)
            }
          }

          if (typeof this.key !== 'undefined') {
            this.dec = new Algorithm().decryptor(this.key.algorithm, this.key.raw, this.iv);
            const be = this.billing_events.addBillingEvent(this.papi, "", "", BillingEvents.DECRYPTION, BillingEvents.UNSTRUCTURED, 0, 1);
          }

          if ((flags & Algorithm.UBIQ_HEADER_V0_FLAG_AAD) !== 0) {
            this.dec.setAAD(Buffer.concat([struct_buf, this.iv, encrypted_key]));
          }
          return this.update_cipher(this.data);
          // Exit the function
        }
      }
    }
  }

  async unwrapkey() {
    const privateKey = await forge.pki.decryptRsaPrivateKey(this.encrypted_private_key, this.srsa);

    const decrypted = await privateKey.decrypt(this.key.wdk, 'RSA-OAEP');

    if (verbose) console.log(`decrypt:unwrapkey:`);
    return decrypted;
  }

  async set_key(response, client_id, algorithm_id, encoded_key) {

    this.key = {};
    this.key.client_id = client_id;
    this.key.algorithm = new Algorithm().findAlgo(algorithm_id);
    this.key.encoded_key = encoded_key

    if (typeof this.encrypted_private_key === 'undefined') {
      const { encrypted_private_key } = response;
      this.encrypted_private_key = encrypted_private_key;
    }

    // Get wrapped data key from response body
    const { wrapped_data_key } = response;

    this.key.wdk = forge.util.decode64(wrapped_data_key);
    // Decrypt the encryped private key using @srsa supplied

    const privateKey = forge.pki.decryptRsaPrivateKey(this.encrypted_private_key, this.srsa);

    const decrypted = privateKey.decrypt(this.key.wdk, 'RSA-OAEP');

    if (this.ubiqConfiguration.key_caching_encrypt) {
      // Cache but don't include raw key
      if (this.ubiqConfiguration.key_caching_unstructured) {
        this.cache.set(this.key.encoded_key, JSON.stringify(this.key))
      }
      this.key.raw = decrypted;

    } else {
      this.key.raw = decrypted;
      // Cache including raw key
      if (this.ubiqConfiguration.key_caching_unstructured) {
        this.cache.set(this.key.encoded_key, JSON.stringify(this.key))
      }
    }
  }

  end() {
    if (verbose) console.log(`decrypt:end`);
    if (!this.decryption_started) {
      throw new Error('Decryption is not Started');
    }

    this.dec.setAuthTag(this.data);
    this.dec.final('binary');

    // Finish the decryption
    this.decryption_started = false;
    delete this.dec;
    this.data = Buffer.from('');
    delete this.key
    return '';
  }

  async update_cipher() {
    const { tag_length } = this.key.algorithm;
    const size = this.data.length - tag_length;
    if (size > 0) {
      const cipher_data = this.data.slice(0, size);
      const res = this.dec.update(cipher_data, 'binary', 'binary');
      this.decryption_started = true;
      this.data = this.data.slice(size, this.data.length);
      return res;
    }
    return undefined;
  }

  async close() {
    if (this.decryption_started) {
      throw new Error('Decryption currently running');
    }

    await this.billingEventsProcessor.close();
    this.billing_events = null;

    if (typeof this.key != 'undefined') {
      delete this.key;
    }
    if (typeof this.data != 'undefined') {
      delete this.data;
    }
    this.cache.clear()
  }

  addReportingUserDefinedMetadata(jsonString) {
    this.billing_events.addUserDefinedMetadata(jsonString);
  }

  getCopyOfUsage() {
    return this.billing_events.getSerializedData();
  }

};
