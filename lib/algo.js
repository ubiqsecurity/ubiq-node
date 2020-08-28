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


const forge = require('node-forge');
const crypto = require('crypto');

module.exports = class Algorithm{
  // We assume that we're going to use AES-256-GCM algorithm for our encryption and decryption
  constructor(){
    this.algo = {}
    this.algo['aes-256-gcm'] = {
      id: 0,
      algorithm: 'aes-256-gcm',
      key_length: 32,
      iv_length: 12,
      tag_length: 16
    },
    this.algo['aes-128-gcm'] = {
      id: 1,
      algorithm: 'aes-128-gcm',
      key_length: 16,
      iv_length: 12,
      tag_length: 16
    }
  }

  getAlgo(name){
    return this.algo[name]
  }

  findAlgo(id){
    var keys = Object.keys(this.algo);
    let algo = this.algo
    var selected_algo = {}
    for(var i = 0; i < keys.length;i++){
      if(algo[keys[i]]['id'] == id){
        selected_algo = algo[keys[i]]
      }
    }

    if(Object.keys(selected_algo).length === 0) {
      console.log('unknown algorithm')
      return 'unknown algorithm';
    }else{
      return selected_algo
    }
  }

  // create an encryptor context
  encryptor(obj, key){
    // key : A byte string containing the key to be used with this encryption
    // If the caller specifies the initialization vector, it must be
    // the correct length and, if so, will be used. If it is not
    // specified, the function will generate a new one
    if(key.length != obj['key_length']){
      console.log('Key length is invalid')
      return false;
    }

    const algorithm = obj['algorithm'];
    const key_encoded = crypto.scryptSync(key, 'salt', 32);
    const iv = crypto.randomBytes(12);
    let encoded = Buffer.from(key, 'binary')

    const cipher = crypto.createCipheriv(algorithm, encoded, iv);

    return [cipher, iv]
  }

  decryptor(obj, key, iv){
    if(key.length != obj['key_length']){
      console.log('Key length is invalid')
      return false;
    }
    if(iv.length != obj['iv_length']){
      console.log('Initialization Vector is invalid')
      return false;
    }

    const algorithm = obj['algorithm'];
    let encoded = Buffer.from(key, 'binary')

    const decipher = crypto.createDecipheriv(algorithm, encoded, iv);

    return decipher
  }
}
