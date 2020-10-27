const fs = require('fs');
const ConfigParser = require('configparser');

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
  // If config_file is undefined or empty string,
  // try to use either standard credentials else credentials.json
  if (!config_file) {
            config_file = require('os').homedir() + '/.ubiq/credentials'
      if (!fs.existsSync(config_file)) {
        config_file = require('os').homedir() + '/.ubiq/credentials.json'
            }
    }
    return(this.load_crendentials(config_file, profile))
  }

  process_json_credentials(credentials_data, profile) {
          var def = {}
    var prof = {}

    if((credentials_data['default'])) {
      def = credentials_data['default']
    }
    if(profile){
      if(credentials_data[profile]) {
        prof = credentials_data[profile]
      }
    }

    let papi =  (prof['ACCESS_KEY_ID']) ? prof['ACCESS_KEY_ID'] : def['ACCESS_KEY_ID']
    let sapi = (prof['SECRET_SIGNING_KEY']) ? prof['SECRET_SIGNING_KEY'] : def['SECRET_SIGNING_KEY']
    let srsa = (prof['SECRET_CRYPTO_ACCESS_KEY'])  ? prof['SECRET_CRYPTO_ACCESS_KEY'] : def['SECRET_CRYPTO_ACCESS_KEY']
    let server = (prof['SERVER']) ? prof['SERVER'] : def['SERVER']

    return(set_attributes(papi, sapi, srsa, server))
  }

  load_credentials_file(credentials_file, profile) {
    const config = new ConfigParser();
    config.read(credentials_file);
    let papi =  (config.get(profile, 'ACCESS_KEY_ID')) ? config.get(profile, 'ACCESS_KEY_ID') : config.get('default', 'ACCESS_KEY_ID')
    let sapi =  (config.get(profile, 'SECRET_SIGNING_KEY'))  ? config.get(profile, 'SECRET_SIGNING_KEY') : config.get('default', 'SECRET_SIGNING_KEY')
    let srsa =  (config.get(profile, 'SECRET_CRYPTO_ACCESS_KEY')) ? config.get(profile, 'SECRET_CRYPTO_ACCESS_KEY') : config.get('default', 'SECRET_CRYPTO_ACCESS_KEY')
    let server =  (config.get(profile, 'SERVER')) ? config.get(profile, 'SERVER') : config.get('default', 'SERVER')
    return(set_attributes(papi, sapi, srsa, server))
  }


  load_crendentials(credentials_file, profile){
    let credentials_data = fs.readFileSync(credentials_file);

    var ret
    try {
             credentials_data = JSON.parse(credentials_data)
       ret = this.process_json_credentials(credentials_data, profile)
    }
    catch (e) {
             // config parser library requires file name, not data
             ret = this.load_credentials_file(credentials_file, profile)
    }
    return ret;

  }
}

module.exports  = {ConfigCredentials, Credentials}
