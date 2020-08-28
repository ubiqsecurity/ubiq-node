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

const fs = require('fs');

function set_attributes(access_key_id, secret_signing_key, secret_crypto_access_key, host){
  let server = (host) ? host : "https://api.ubiqsecurity.com"

   if (server.indexOf('http://') !== 0 && server.indexOf('https://') !== 0) {
        server = 'https://' + server
   }

  return {
    access_key_id: access_key_id,
    secret_signing_key: secret_signing_key,
    secret_crypto_access_key: secret_crypto_access_key,
    host: server
  }
}

class Credentials{
  constructor(access_key_id, secret_signing_key, secret_crypto_access_key, host){
    this.access_key_id = (access_key_id) ? access_key_id : process.env.UBIQ_ACCESS_KEY_ID
    this.secret_signing_key = (secret_signing_key) ? secret_signing_key : process.env.UBIQ_SECRET_SIGNING_KEY
    this.secret_crypto_access_key = (secret_crypto_access_key) ? secret_crypto_access_key : process.env.UBIQ_SECRET_CRYPTO_ACCESS_KEY
    this.host = (host) ? host : process.env.UBIQ_SERVER
    return(set_attributes(this.access_key_id, this.secret_signing_key, this.secret_crypto_access_key, this.host))
  }
}

class ConfigCredentials{
  constructor(config_file, profile) {
    fs.exists(config_file, (exists) => {
      if(!exists){
        config_file = '~/.ubiq/credentials.json'
      }
    });

    return(this.load_crendentials(config_file, profile))
  }

  load_crendentials(credentials_file, profile){
    let crentials_data = fs.readFileSync(credentials_file);
    crentials_data = JSON.parse(crentials_data)
    var def = {}
    var prof = {}

    if(typeof crentials_data['default'] != 'undefined'){
      def = crentials_data['default']
    }
    if(profile){
      if(typeof crentials_data[profile] != 'undefined'){
        prof = crentials_data[profile]
      }
    }

    let papi =  typeof prof['ACCESS_KEY_ID'] != 'undefined' ? prof['ACCESS_KEY_ID'] : def['ACCESS_KEY_ID'];
    let sapi = typeof prof['SECRET_SIGNING_KEY'] != 'undefined' ? prof['SECRET_SIGNING_KEY'] : def['SECRET_SIGNING_KEY'];
    let srsa = typeof prof['SECRET_CRYPTO_ACCESS_KEY'] != 'undefined' ? prof['SECRET_CRYPTO_ACCESS_KEY'] : def['SECRET_CRYPTO_ACCESS_KEY'];
    let server = typeof prof['SERVER'] != 'undefined' ? prof['SERVER'] : def['SERVER']

    return(set_attributes(papi, sapi, srsa, server))
  }
}

module.exports  = {ConfigCredentials, Credentials}