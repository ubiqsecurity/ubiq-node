// Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains the property
// of Ubiq Security, Inc. The intellectual and technical concepts contained
// herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
// covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this
// information or reproduction of this material is strictly forbidden
// unless prior written permission is obtained from Ubiq Security, Inc.
//
// Your use of the software is expressly conditioned upon the terms
// and conditions available at:
//
//     https://ubiqsecurity.com/legal

const auth = require('./auth.js')
const forge = require('node-forge');
const fetch = require('node-fetch');
const struct = require('python-struct');
const Algorithm = require('./algo.js')


module.exports = class Decryption{
  // Initialize the decryption module object
  constructor(params){
    // The client's public API key (used to identify the client to the server
    this.papi = params.access_key_id
    // The client's secret API key (used to authenticate HTTP requests)
    this.sapi = params.secret_signing_key
    // The client's secret RSA encryption key/password (used to decrypt the client's RSA key from the server). This key is not retained by this object.
    this.srsa = params.secret_crypto_access_key
    // Set host, either the default or the one given by caller
    this.host = params.host
    this.endpoint_base = params.host + '/api/v0'
    this.endpoint = '/api/v0/decryption/key'
    this.decryption_started = false
    this.decryption_ready = true
  }

  begin(){
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

    if(!this.decryption_ready){
      console.log('Decryption is not ready')
      return;
    }

    if(this.decryption_started){
      console.log('Decryption already in progress')
      return;
    }

    // Start the decryption process
    this.decryption_started = true

    this.data = Buffer.from('')
    return this.data
  }

  async update(data){
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
    if(!this.decryption_started){
      console.log('Decryption is not Started')
      return;
    }

    // Append the incoming data in the internal data buffer
    let arr = [this.data, data]
    // Concat the two buffers to form single buffer
    this.data = Buffer.concat(arr)

    if(typeof this.key != 'undefined'){
      return this.update_cipher(data)
    }

    if(typeof this.key == 'undefined' || typeof this.dec == 'undefined'){

      let struct_length = struct.sizeOf('!BBBBH');
      // Does the buffer contain enough of the header to
      // determine the lengths of the initialization vector
      // and the key?

      if(this.data.length > struct_length){
        let structed_string = this.data.slice(0,struct_length)

        let struct_buf = new Buffer.from(structed_string, "binary")

        let arr = struct.unpack('!BBBBH',struct_buf)

        let version = arr[0]
        let flags = arr[1]
        let algorithm_id = arr[2]
        let iv_length = arr[3]
        let key_length = arr[4]

        // verify version is 0 and flags are correct
        if((version != 0) || (flags & ~Algorithm.UBIQ_HEADER_V0_FLAG_AAD) != 0) {
          return;
        }

        // Does the buffer contain the entire header?
        if(this.data.length > struct_length + iv_length + key_length){
          // Extract the initialization vector
          this.iv = this.data.slice(struct_length, struct_length + iv_length)
          // Extract the encryped key
          let encrypted_key = this.data.slice(struct_length + iv_length, key_length + struct_length + iv_length)

          let encoded_key = forge.util.encode64(encrypted_key.toString('binary'))

          // Shrink the data
          this.data = this.data.slice(key_length + struct_length + iv_length, this.data.length)

          // let cipher_data_size = this.data.length - 16

          // get the tag
          // this.tag = this.data.substring(0, 16)

          // Get the data to be decrypted
          // this.data = this.data.substring(16,this.data.length)

          var md = forge.md.sha512.create();
          md.update(encoded_key)

          let client_id = md.digest().data
          // if key does not exist
          if (typeof this.key == "undefined") {
            let url = this.endpoint_base + '/decryption/key'
            let query = {encrypted_data_key: encoded_key}
            let headers = auth.headers(this.papi, this.sapi, this.endpoint, query, this.host, 'post')

            let otherParam = {
              headers: headers,
              body: JSON.stringify(query),
              method: 'POST'
            }

            const response = await fetch(url, otherParam)
            if(response.status == 200){
              let data = await response.json()
              this.set_key(data, client_id, algorithm_id)
              if ((flags & Algorithm.UBIQ_HEADER_V0_FLAG_AAD) != 0) {
                this.dec.setAAD(Buffer.concat([struct_buf, this.iv, encrypted_key]))
              }
              return this.update_cipher(this.data)
            }
            else{
              console.log(`HTTPError Response: Expected 200, got ${response.status}`)
              // Exit the function
              return;
            }
          }
        }
      }
    }



  }

  set_key(response, client_id, algorithm_id){
    this.key = {}
    this.key['finger_print'] = response['key_fingerprint']
    this.key['client_id'] = client_id
    this.key['session'] = response['encryption_session']
    this.key['algorithm'] = new Algorithm().findAlgo(algorithm_id)
    this.key['uses'] = 0

    let encrypted_private_key = response['encrypted_private_key']
    // Get wrapped data key from response body
    let wrapped_data_key = response['wrapped_data_key']

    let wdk = forge.util.decode64(wrapped_data_key)
    // Decrypt the encryped private key using @srsa supplied

    let privateKey = forge.pki.decryptRsaPrivateKey(encrypted_private_key, this.srsa);

    var decrypted = privateKey.decrypt(wdk, 'RSA-OAEP');

    this.key['raw'] = decrypted

    if(typeof this.key != "undefined"){
      this.dec = new Algorithm().decryptor(this.key['algorithm'], this.key['raw'], this.iv)
      this.key['uses'] = this.key['uses'] + 1;
    }
  }

  end(){
    if(!this.decryption_started){
      console.log('Decryption is not Started')
      return;
    }

    this.dec.setAuthTag(this.data)
    this.dec.final('binary')

    // Finish the decryption
    this.decryption_started = false
    return ''
  }

  async update_cipher(data){
    let tag_length = this.key['algorithm']['tag_length']
    let size = this.data.length - tag_length
    // console.log('***** DECRYPTING *****')
    if(size > 0){
      let cipher_data = this.data.slice(0, size)
      let res = this.dec.update(cipher_data, 'binary', 'binary')
      this.decryption_started = true
      this.data = this.data.slice(size, this.data.length)
      return res
    }
  }

  async close(){
    if(this.decryption_started){
      console.log('Decryption currently running')
      return;
    }

    if(this.key){
      if(this.key['uses'] > 0){
        let query_url = `${this.endpoint}/${this.key['finger_print']}/${this.key['session']}`
        let url = `${this.endpoint_base}/decryption/key/${this.key['finger_print']}/${this.key['session']}`
        let query = {uses: this.key['uses']}
        let headers = auth.headers(this.papi, this.sapi, query_url, query, this.host, 'patch')
        let otherParam = {
          headers: headers,
          body: JSON.stringify(query),
          method: 'PATCH'
        }

        const response = await fetch(url, otherParam)
        if(response.status == 204){
          delete this.data
          delete this.key
          return ''
        }
        // For any other response status code
        else{
          console.log(`HTTPError Response: Expected 204, got ${response.status}`)
          // Exit the function
          return;
        }
      }
    }
  }
}
