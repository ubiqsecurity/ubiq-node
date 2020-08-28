# Ubiq Security Node.js Library

The Ubiq Security Node library provides convenient interaction with the
Ubiq Security Platform API from applications written in the Javascript language.
It includes a pre-defined set of classes that will provide simple interfaces
to encrypt and decrypt data

## Documentation

See the [Node API docs][apidocs].


## Installation

#### Using the npm or yarn package managers:
You may want to make sure you are running the latest version of npm or yarn by first executing
```sh
npm install -g npm
# or
npm install -g yarn
```

Install the ubiq-security package with:


```sh
npm install ubiq-security
# or
yarn add ubiq-security
```
### Requirements

All dependencies are pre-required in the module itself.


## Usage

The library needs to be configured with your account credentials which is
available in your [Ubiq Dashboard][dashboard] [Credentials][credentials]   The credentials can be 
explicitly set, set using environment variables, loaded from an explicit file
or read from the default location [~/.ubiq/credentials.json]

Require the Security Client module in your JS class.

```javascript
const ubiq = require('ubiq-security')
```

Read credentials from a specific file and use a specific profile

```javascript
const credentials = new ubiq.ConfigCredentials(credentials_file, profile)
```

### Read credentials from ~/.ubiq/credentials.json and use the default profile
```javascript
const credentials = new ubiq.ConfigCredentials()
```

### Use the following environment variables to set the credential values
UBIQ_ACCESS_KEY_ID  
UBIQ_SECRET_SIGNING_KEY  
UBIQ_SECRET_CRYPTO_ACCESS_KEY  
```javascript
const credentials = new ubiq.Credentials()
```

### Explicitly set the credentials
```javascript
const credentials = new Credentials('<access_key_id>', '<secret_signing_key>', '<secret_crypto_access_key>')
```


### Encrypt a simple block of data

Pass credentials and data into the encryption function.  The encrypted data will be returned.

```javascript
const ubiq = require('ubiq-security')

const encrypted_data = await ubiq.encrypt(credentials, plainntext_data)
```
### Decrypt a simple block of data

Pass credentials and encrypted data into the decryption function.  The plaintext data
will be returned.

```javascript
const ubiq = require('ubiq-security')

const plainttext_data = await ubiq.decrypt(credentials, encrypted_data)
```
### Encrypt a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance begin method
- Call the encryption instance update method repeatedly until all the data is processed
- Call the encryption instance end method
- Call the encryption instance close method
```javascript
const ubiq = require('ubiq-security')

// Process 1 MiB of plaintext data at a time
const BLOCK_SIZE = 1024 * 1024

/Rest of the program
...
  var readStream = fs.createReadStream(input_file,{ highWaterMark: BLOCK_SIZE  });

  let enc = await new ubiq.Encryption(credentials, 1);
  # Write out the header information
  let encrypted_data = enc.begin()
  
  readStream.on('data', function(chunk) {
    encrypted_data += enc.update(chunk)
  }).on('end', function() {
      encrypted_data += enc.end()
      enc.close()
  });
```
### Decrypt a large data element where data is loaded in chunks

- Create an instance of the decryption object using the credentials.
- Call the decryption instance begin method
- Call the decryption instance update method repeatedly until all the data is processed
- Call the decryption instance end method
- Call the decryption instance close method


```javascript
const ubiq = require('ubiq-security')

// Process 1 MiB of plaintext data at a time
const BLOCK_SIZE = 1024 * 1024

  let dec = new ubiq.Decryption(credentials)
  let plainttext_data = dec.begin()

  readStream.on('data', async function(chunk) {
    readStream.pause()
    await dec.update(chunk).then(function(response){
    if(response){
        plainttext_data += response
      }
    })
    readStream.resume()
  }).on('end', async function() {
      plainttext_data += dec.end()
      dec.close()
  });
```
[dashboard]:https://dev.ubiqsecurity.com/docs/dashboard
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[apidocs]:https://dev.ubiqsecurity.com/docs/api
