# Ubiq Security Node.js Library

The Ubiq Security Node library provides convenient interaction with the
Ubiq Security Platform API from applications written in the Javascript language.
It includes a pre-defined set of classes that will provide simple interfaces
to encrypt and decrypt data

This library also incorporates Ubiq Format Preserving Encryption (eFPE).  eFPE allows encrypting so that the output cipher text is in the same format as the original plaintext. This includes preserving special characters and control over what characters are permitted in the cipher text. For example, consider encrypting a social security number '123-45-6789'. The cipher text will maintain the dashes and look something like: 'W$+-qF-oMMV'.


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

To build and install directly from a clone of the gitlab repository source:

```sh
git clone https://gitlab.com/ubiqsecurity/ubiq-node.git
cd ubiq-node
npm install
```

### Requirements

Node.js version 16 or later
npm version 6 or later

All dependencies are pre-required in the module itself.


## Usage

The library needs to be configured with your account credentials which is
available in your [Ubiq Dashboard][dashboard] [Credentials][credentials]   The credentials can be 
explicitly set, set using environment variables, loaded from an explicit file
or read from the default location [~/.ubiq/credentials].  A configuration can also be supplied 
to control how usage is reported back to the ubiq servers.  The configuration file can be loaded from an explict file or read from the default location [~/.ubiq/configuration].  See [below](#Configuration%20File) for a sample configuration file and content description.

Require the Security Client module in your JS class.

```javascript
const ubiq = require('ubiq-security')
```

Read credentials from a specific file and use a specific profile

```javascript
const credentials = new ubiq.ConfigCredentials(credentials_file, profile)
```

Read configuration from a specific file

```javascript
const configuration = new ubiq.Configuration(configuration)
```


### Read credentials from ~/.ubiq/credentials and use the default profile
```javascript
const credentials = new ubiq.ConfigCredentials()
```

### Read configuration from ~/.ubiq/configuration
```javascript
const configuration = new ubiq.Configuration()
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

const encrypted_data = await ubiq.encrypt(credentials, plaintext_data)
```
### Decrypt a simple block of data

Pass credentials and encrypted data into the decryption function.  The plaintext data
will be returned.

```javascript
const ubiq = require('ubiq-security')

const plaintext_data = await ubiq.decrypt(credentials, encrypted_data)
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

//Rest of the program
...
  var readStream = fs.createReadStream(input_file,{ highWaterMark: BLOCK_SIZE  });

  let enc = await new ubiq.Encryption(credentials, 1);
  // Write out the header information
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
  let plaintext_data = dec.begin()

  readStream.on('data', async function(chunk) {
    readStream.pause()
    await dec.update(chunk).then(function(response){
    if(response){
        plaintext_data += response
      }
    })
    readStream.resume()
  }).on('end', async function() {
      plaintext_data += dec.end()
      dec.close()
  });
```

## Ubiq Format Preserving Encryption

This library incorporates Ubiq Format Preserving Encryption (eFPE).

## Requirements

-   Please follow the same requirements as described above for the non-eFPE functionality.
-   This library has dependencies on ubiqsecurity-fpe library available for download in the Ubiq GitHub/GitLab repository.

## Usage

You will need to obtain account credentials in the same way as described above for conventional encryption/decryption. When
you do this in your [Ubiq Dashboard][dashboard] [credentials][credentials], you'll need to enable the eFPE option.
The credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).  The configuration file can also be specified, read from the default location, or left to default values.


Require the Security Client module in your JS class.

```javascript
const ubiq = require('ubiq-security')
```


### Encrypt a social security text field - simple interface
Pass credentials, the name of a Field Format Specification, FFS, and data into the encryption function.
The encrypted data will be returned.

```javascript
const FfsName = "SSN";
const plainText = "123-45-6789";

const credentials = new ubiq.ConfigCredentials('./credentials', 'default');

const encrypted_data = await ubiq.fpeEncryptDecrypt.Encrypt({
        ubiqCredentials: credentials,
        ffsname: FfsName,
        data: plainText});
        
console.log('ENCRYPTED ciphertext= ' + encrypted_data + '\n');
```

### Decrypt a social security text field - simple interface
Pass credentials, the name of a Field Format Specification, FFS, and data into the decryption function.
The decrypted data will be returned.

```javascript

const FfsName = "SSN";
const cipher_text = "300-0E-274t";

const credentials = new ubiq.ConfigCredentials('./credentials', 'default');

const decrypted_text = await ubiq.fpeEncryptDecrypt.Decrypt({
        ubiqCredentials: credentials,
        ffsname: FfsName,
        data: cipher_text});
        
console.log('DECRYPTED decrypted_text= ' + decrypted_text + '\n');
```


### Encrypt a social security text field - bulk interface
Create an FpeEncryptDecrypt object with credentials and then allow repeated calls to encrypt / decrypt
data using a Field Format Specification and the data.  Cipher text will be returned.

```javascript
const FfsName = "SSN";
const plainText = "123-45-6789";

const credentials = new ubiq.ConfigCredentials('./credentials', 'default');
const configuration = new ubiq.Configuration();

const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials : credentials, ubiqConfiguration: configuration });

const encrypted_data = await ubiqEncryptDecrypt.EncryptAsync(
        FfsName,
        plainText
      );
        
console.log('ENCRYPTED ciphertext= ' + encrypted_data + '\n');
ubiqEncryptDecrypt.close();
```
### Decrypt a social security text field - bulk interface
Create an Encryption / Decryption object with the credentials and then repeatedly decrypt
data using a Field Format Specification, FFS, and the data.  The decrypted data will be returned after each call.


Note that you would only need to create the "ubiqEncrFpeEncryptDecryptyptDecrypt" object once for any number of EncryptAsync and DecryptAsync calls, for example when you are bulk processing many such encrypt / decrypt operations in a session.


```javascript
const cipher_text = "300-0E-274t";
const credentials = new ubiq.ConfigCredentials('./credentials', 'default');
const configuration = new ubiq.Configuration();

const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials: credentials, ubiqConfiguration: configuration });

const decrypted_text = await ubiqEncryptDecrypt.DecryptAsync(
        FfsName,
        cipher_text
      );
console.log('DECRYPTED decrypted_text= ' + decrypted_text + '\n');
ubiqEncryptDecrypt.close();
```
### Encrypt For Search

The same plaintext data will result in different cipher text when encrypted using different data keys.  The Encrypt For Search function will encrypt the same plain text for a given dataset using all previously used data keys.  This will provide a collection of cipher text values that can be used when searching for existing records where the data was encrypted and the specific version of the data key is not known in advance.

```javascript
const credentials = new ubiq.ConfigCredentials('./credentials', 'default');
const configuration = new ubiq.Configuration('./configuration');
const dataset_name = "SSN";
const plainText = "123-45-6789";

const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials: credentials, ubiqConfiguration: configuration });

const searchText = await ubiqEncryptDecrypt.EncryptForSearchAsync(
  dataset_name,
  plainText,
  []);

```
Additional information on how to use these FFS models in your own applications is available by contacting
Ubiq. You may also view some use-cases implemented in the unit test [UbiqSecurityFpeEncryptDecrypt.test.js] and the sample application [UbiqSampleFPE.js] source code

#### Configuration File

A sample configuration file is shown below.  The configuration is in JSON format.  The <b>event_reporting</b> section contains values to control how often the usage is reported.  

- <b>wake_interval</b> indicates the number of seconds to sleep before waking to determine if there has been enough activity to report usage
- <b>minimum_count</b> indicates the minimum number of usage records that must be queued up before sending the usage
- <b>flush_interval</b> indicates the sleep interval before all usage will be flushed to server.
- <b>trap_exceptions</b> indicates whether exceptions encountered while reporting usage will be trapped and ignored or if it will become an error that gets reported to the application

   #### NodeJs specific parameters
  - <b>lock_sleep_before_retry</b> indicates the number of milliseconds to wait before trying to lock a cache resource if the first attempt fails
  - <b>lock_max_retry_count</b> indicates the number of times to try to lock a cache resource before giving up

```json
{
  "event_reporting": {
    "wake_interval": 1,
    "minimum_count": 2,
    "flush_interval": 2,
    "trap_exceptions": false
  },
  "nodejs" : {
     "lock_sleep_before_retry" : 250,
     "lock_max_retry_count" : 15
  }
}
```

[dashboard]:https://dashboard.ubiqsecurity.com
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[apidocs]:https://dev.ubiqsecurity.com/docs/api
[UbiqSecurityFpeEncryptDecrypt.test.js]:https://gitlab.com/ubiqsecurity/ubiq-node/-/blob/master/tests/UbiqSecurityFpeEncryptDecrypt.test.js
[UbiqSampleFPE.js]:https://gitlab.com/ubiqsecurity/ubiq-node/-/blob/master/example/ubiq_sample_fpe.js
[configuration]:README.md#L317