const forge = require('node-forge');
const fetch = require('node-fetch');
const struct = require('python-struct');
const auth = require('./auth');
const Algorithm = require('./algo');

module.exports = class Encryption {
  constructor(params, uses) {
    // The client's public API key (used to identify the client to the server
    this.papi = params.access_key_id;
    // The client's secret API key (used to authenticate HTTP requests)
    this.sapi = params.secret_signing_key;
    // The client's secret RSA encryption key/password (used to decrypt the client's RSA key from the server). This key is not retained by this object.
    this.srsa = params.secret_crypto_access_key;
    // Set host, either the default or the one given by caller
    this.host = params.host;
    this.endpoint_base = `${this.host}/api/v0`;
    this.endpoint = '/api/v0/encryption/key';
    // Build the endpoint URL
    this.url = `${this.endpoint_base}/encryption/key`;
    // Build the Request Body with the number of uses of key provided
    const query = { uses };
    // Retrieve the necessary headers to make the request using Auth Object
    const headers = auth.headers(this.papi, this.sapi, this.endpoint, query, this.host, 'post');
    // Build the request into a variable
    this.otherParam = {
      headers,
      body: JSON.stringify(query),
      method: 'POST',
    };

    this.encryption_started = false;
    this.encryption_ready = true;
    // Request a new encryption key from the server. if the request
    // fails, the function raises a HTTPError indicating
    // the status code returned by the server. this exception is
    // propagated back to the caller
    return new Promise(async (resolve, reject) => {
      try {
        // Wait for server response
        const response = await fetch(this.url, this.otherParam);
        // If response status is 201 Created
        if (response.status === 201) {
          const data = await response.json();
          this.set_key(data);
        }
        // For any other response status code
        else {
          console.log(`HTTPError Response: Expected 201, got ${response.status}`);
          // Exit the function
          return;
        }
      } catch (ex) {
        // Reject the promise in case of any exception
        return reject(ex);
      }
      resolve(this);
    });
  }

  set_key(data) {
    // The code below largely assumes that the server returns
    // a json object that contains the members and is formatted
    // according to the Voltron REST specification.
    // Make the key object for encryption
    this.key = {};
    this.key.id = data.key_fingerprint;
    this.key.session = data.encryption_session;
    this.key.security_model = data.security_model;
    this.key.algorithm = data.security_model.algorithm.toLowerCase();
    this.key.max_uses = data.max_uses;
    this.key.encrypted = forge.util.decode64(data.encrypted_data_key);
    this.key.uses = 0;
    // Get encrypted private key from response body
    const { encrypted_private_key } = data;
    // Get wrapped data key from response body
    const { wrapped_data_key } = data;
    const wdk = forge.util.decode64(wrapped_data_key);
    // Decrypt the encryped private key using @srsa supplied
    const privateKey = forge.pki.decryptRsaPrivateKey(encrypted_private_key, this.srsa);
    const decrypted = privateKey.decrypt(wdk, 'RSA-OAEP');
    this.key.raw = decrypted;
    // Build the algorithm object
    this.algo = new Algorithm().getAlgo(this.key.algorithm);
  }

  begin() {
    // Begin the encryption process
    // When this function is called, the encryption object increments
    // the number of uses of the key and creates a new internal context
    // to be used to encrypt the data.

    // If the encryption object is not yet ready to be used, throw an error
    if (!this.encryption_ready) {
      console.log('Encryption not ready');
      return;
    }

    // If the encryption has already started
    if (this.encryption_started) {
      console.log('Encryption already in progress');
      return;
    }

    // If the maximum uses of key exceed current no of uses
    if (this.key.uses > this.key.max_uses) {
      console.log('Maximum key uses exceeded');
      return;
    }
    this.key.uses += 1;
    // create a new Encryption context and initialization vector
    const cipher_values = new Algorithm().encryptor(this.algo, this.key.raw);
    // get encryption context
    this.enc = cipher_values[0];
    // get initialization vector
    this.iv = cipher_values[1];
    // Pack the result into bytes to get an array buffer
    const array_buf = struct.pack('!BBBBH', 0, Algorithm.UBIQ_HEADER_V0_FLAG_AAD, this.algo.id, this.iv.length, this.key.encrypted.length);

    const string_buf = Buffer.from(this.key.encrypted, 'binary');

    const buf_arr = [array_buf, this.iv, string_buf];

    const main_buf = Buffer.concat(buf_arr);

    this.enc.setAAD(main_buf);
    this.encryption_started = true;
    return main_buf;
  }

  update(data) {
    // Encryption of some plain text is perfomed here
    // Any cipher text produced by the operation is returned
    if (!this.encryption_started) {
      console.log('Encryption is not Started');
      return;
    }

    const res = this.enc.update(data, 'binary', 'binary');

    const update = Buffer.from(res, 'binary');
    return update;
  }

  end() {
    // This function finalizes the encryption (producing the final
    // cipher text for the encryption, if necessary) and adds any
    // authentication information (if required by the algorithm).
    // Any data produced is returned by the function.

    if (!this.encryption_started) {
      console.log('Encryption is not Started');
      return;
    }

    // Finalize an encryption
    let encrypted = this.enc.final('binary');

    encrypted = Buffer.from(encrypted, 'binary');
    const tag = this.enc.getAuthTag();
    const arr = [encrypted, tag];
    this.encryption_started = false;
    // Add the tag to the cipher text
    return Buffer.concat(arr);
  }

  close() {
    if (this.encryption_started) {
      console.log('Encryption currently running');
      return;
    }
    //  If the key was used less times than was requested, send an update to the server
    if (this.key.uses < this.key.max_uses) {
      // Build the query URL to be used for calculating headers
      const query_url = `${this.endpoint}/${this.key.id}/${this.key.session}`;
      // Build the request URL
      const url = `${this.endpoint_base}/encryption/key/${this.key.id}/${this.key.session}`;
      // Build the actual query
      const query = { actual: this.key.uses, requested: this.key.max_uses };
      // Retrieve headers
      const headers = auth.headers(this.papi, this.sapi, query_url, query, this.host, 'patch');
      const otherParam = {
        headers,
        body: JSON.stringify(query),
        method: 'PATCH',
      };

      return new Promise(async (resolve, reject) => {
        try {
          const response = await fetch(url, otherParam);
          // Success if response is 204 No content
          if (response.status === 204) {
            delete this.key;
          } else { // For any other response status code
            console.log(`HTTPError Response: Expected 201, got ${response.status}`);
            // Exit the function
            return;
          }
        } catch (ex) {
          return reject(ex);
        }
        // Return Blank for success
        resolve('');
      });
    }
  }
};
