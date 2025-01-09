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
to control how usage is reported back to the ubiq servers.  The configuration file can be loaded from an explicit file or read from the default location [~/.ubiq/configuration].  See [below](#Configuration%20File) for a sample configuration file and content description.  The credentials object needs to be initialized using the configuration object and the credentials.initAsync method.  The credentials object only needs to be initialized one time, even if it is used to encrypt / decrypt many different object. 

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
const configuration = new ubiq.Configuration(configurationFile)

// Use the configuration to finish initalizing the credentials
await credentials.initAsync(configuration)

```


### Read credentials from ~/.ubiq/credentials and use the default profile
```javascript
const credentials = new ubiq.ConfigCredentials()
```

### Read configuration from ~/.ubiq/configuration
```javascript
const configuration = new ubiq.Configuration()

// Use the configuration to finish initalizing the credentials
await credentials.initAsync(configuration)
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

### IDP integration
Ubiq currently supports both Okta and Entra IDP integration.  Instead of using the credentials provided when creating the API Key, the username (email) and password will be used to authenticate with the IDP and provide access to the Ubiq platform.

### Use the following environment variables to set the credential values
IDP_USERNAME  
IDP_PASSWORD  
```javascript
const credentials = new ubiq.Credentials()
```

### Explicitly set the credentials
```javascript
const credentials = new Credentials(null,null,null,null, <username>, <password>)
```


### Encrypt a simple block of data

Pass credentials and data into the encryption function.   The encrypted data will be returned.

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

### Encrypt several objects using the same data encryption key (fewer calls to the server)

In this example, the same data encryption key is used to encrypt several different plain text objects, object1 .. objectn.  In each case, a different initialization vector, IV, is automatically used but the ubiq platform is not called to obtain a new data encryption key, resulting in better throughput.  For data security reasons, you should limit n to be less than 2^32 (4,294,967,296) for each unique data encryption key.

1. Create an encryption object using the credentials.
2. Repeat following three steps as many times as appropriate
* Call the encryption instance begin method
*  Call the encryption instance update method repeatedly until a single object's data is processed
*  Call the encryption instance end method
3. Call the encryption instance close method
```javascript
  const ubiq = require('ubiq-security')

  let enc = await new ubiq.Encryption(credentials, 1);

  // object1 is a full plain text object
  let encrypted_1 = enc.begin()
  encrypted_1 += enc.update(object1)
  encrypted_1 += enc.end()
  // Do something with the encrypted data

  // In this case, object2 is broken into two pieces, object2_part1 and object2_part2
  let encrypted_2 = enc.begin()
  encrypted_2 += enc.update(object2_part1)
  encrypted_2 += enc.update(object2_part2)
  encrypted_2 += enc.end()
  // Do something with the encrypted data

  ...

  // objectn is a plain text object
  let encrypted_n = enc.begin()
  encrypted_n += enc.update(objectn)
  encrypted_n += enc.end()
  // Do something with the encrypted data

  // Encryption of n objects using same data encryption key is complete.  Free resources
  enc.close()

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

## Ubiq Structured Encryption

This library incorporates Ubiq Structured Encryption.

## Requirements

-   Please follow the same requirements as described above for the unstructured functionality.

## Usage

You will need to obtain account credentials in the same way as described above for conventional encryption/decryption. When
you do this in your [Ubiq Dashboard][dashboard] [credentials][credentials], you'll need to enable access to structured datasets.
The credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).  The configuration file can also be specified, read from the default location, or left to default values.


Require the Security Client module in your JS class.

```javascript
const ubiq = require('ubiq-security')
```




### Encrypt a social security text field
Create an structured encryption object using the credentials.  Then pass the name of a structured dataset and data into the encryption function and the encrypted data will be returned.

```javascript
const DatasetName = "SSN";
const plainText = "123-45-6789";

const credentials = new ubiq.ConfigCredentials('./credentials', 'default');
const configuration = new ubiq.Configuration();

// Use the configuration to finish initalizing the credentials
await credentials.initAsync(configuration)

const ubiqEncryptDecrypt = new ubiq.structuredEncryptDecrypt.StructuredEncryptDecrypt({ ubiqCredentials : credentials, ubiqConfiguration: configuration });

const encrypted_data = await ubiqEncryptDecrypt.EncryptAsync(
        DatasetName,
        plainText
      );
        
console.log('ENCRYPTED ciphertext= ' + encrypted_data + '\n');
ubiqEncryptDecrypt.close();
```
### Decrypt a social security text field
Create an structured encryption object using the credentials.  Then pass the name of a structured dataset and data into the decrypt function and the decrypted data will be returned.

Note that you would only need to create the "StructuredEncryptDecrypt" object once for any number of EncryptAsync and DecryptAsync calls, for example when you are bulk processing many such encrypt / decrypt operations in a session.


```javascript
const cipher_text = "300-0E-274t";
const credentials = new ubiq.ConfigCredentials('./credentials', 'default');
const configuration = new ubiq.Configuration();

// Use the configuration to finish initalizing the credentials
await credentials.initAsync(configuration)

const ubiqEncryptDecrypt = new ubiq.structuredEncryptDecrypt.StructuredEncryptDecrypt({ ubiqCredentials: credentials, ubiqConfiguration: configuration });

const decrypted_text = await ubiqEncryptDecrypt.DecryptAsync(
        DatasetName,
        cipher_text
      );
console.log('DECRYPTED decrypted_text= ' + decrypted_text + '\n');
ubiqEncryptDecrypt.close();
```

### Custom Metadata for Usage Reporting
There are cases where a developer would like to attach metadata to usage information reported by the application.  Both the structured and unstructured interfaces allow user_defined metadata to be sent with the usage information reported by the libraries.

The <b>addReportingUserDefinedMetadata</b> function accepts a string in JSON format that will be stored in the database with the usage records.  The string must be less than 1024 characters and be a valid JSON format.  The string must include both the <b>{</b> and <b>}</b> symbols.  The supplied value will be used until the object goes out of scope.  Due to asynchronous processing, changing the value may be immediately reflected in subsequent usage.  If immediate changes to the values are required, it would be safer to create a new encrypt / decrypt object and call the <b>addReportingUserDefinedMetadata</b> function with the new values.

Examples are shown below.
```javascript
  ...
  const ubiqEncryptDecrypt = new ubiq.structuredEncryptDecrypt.StructuredEncryptDecrypt({ ubiqCredentials: credentials, ubiqConfiguration: configuration });
  ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{\"some_meaningful_flag\" : true }')

  // Structured Encrypt and Decrypt operations
```

```javascript
  ...
  let enc = await new ubiq.Encryption(credentials, 1);
  enc.addReportingUserDefinedMetadata('{\"some_key\" : \"some_value\" }')
   ....
  // Unstructured Encrypt operations
```
### Retrieve Current Usage
Within an encryption session, either Encrypt or Decrypt, the client library can retrieve a copy of the unreported events.  This is for read only purposes and has the potential to be different each time it is called due to encrypt / decrypt activities and the asynchronous event billing process.
```javascript
  ...
  const ubiqEncryptDecrypt = new ubiq.structuredEncryptDecrypt.StructuredEncryptDecrypt({ ubiqCredentials: credentials, ubiqConfiguration: configuration });
  ubiqEncryptDecrypt.addReportingUserDefinedMetadata('{\"some_meaningful_flag\" : true }')
  let cipherText = await ubiqEncryptDecrypt.EncryptAsync(
    dataset_name,
    plainText,
    tweakFF1);
  let str = ubiqEncryptDecrypt.getCopyOfUsage();
...
```
### Encrypt For Search

The same plaintext data will result in different cipher text when encrypted using different data keys.  The Encrypt For Search function will encrypt the same plain text for a given dataset using all previously used data keys.  This will provide a collection of cipher text values that can be used when searching for existing records where the data was encrypted and the specific version of the data key is not known in advance.

```javascript
const credentials = new ubiq.ConfigCredentials('./credentials', 'default');
const configuration = new ubiq.Configuration('./configuration');

// Use the configuration to finish initalizing the credentials
await credentials.initAsync(configuration)

const dataset_name = "SSN";
const plainText = "123-45-6789";

const ubiqEncryptDecrypt = new ubiq.structuredEncryptDecrypt.StructuredEncryptDecrypt({ ubiqCredentials: credentials, ubiqConfiguration: configuration });

const searchText = await ubiqEncryptDecrypt.EncryptForSearchAsync(
  dataset_name,
  plainText,
  []);

```
Additional information on how to use these structured datasets in your own applications is available by contacting
Ubiq. You may also view some use-cases implemented in the unit test [UbiqSecurityStructuredEncryptDecrypt.test.js] and the sample application [UbiqSampleStructured.js] source code

#### Configuration File

A sample configuration file is shown below.  The configuration is in JSON format.  The <b>event_reporting</b> section contains values to control how often the usage is reported.  

- <b>wake_interval</b> indicates the number of seconds to sleep before waking to determine if there has been enough activity to report usage
- <b>minimum_count</b> indicates the minimum number of usage records that must be queued up before sending the usage
- <b>flush_interval</b> indicates the sleep interval before all usage will be flushed to server.
- <b>trap_exceptions</b> indicates whether exceptions encountered while reporting usage will be trapped and ignored or if it will become an error that gets reported to the application
- <b>timestamp_granularity</b> indicates the how granular the timestamp will be when reporting events.  Valid values are
  - "NANOS"  
    // DEFAULT: values are reported down to the nanosecond resolution when possible
  - "MILLIS"  
  // values are reported to the millisecond
  - "SECONDS"  
  // values are reported to the second
  - "MINUTES"  
  // values are reported to minute
  - "HOURS"  
  // values are reported to hour
  - "HALF_DAYS"  
  // values are reported to half day
  - "DAYS"  
  // values are reported to the day

   #### NodeJs specific parameters
  - <b>lock_sleep_before_retry</b> indicates the number of milliseconds to wait before trying to lock a cache resource if the first attempt fails
  - <b>lock_max_retry_count</b> indicates the number of times to try to lock a cache resource before giving up

  #### Key Caching
  The <b>key_caching</b> section contains values to control how and when keys are cached.

  - <b>ttl_seconds</b> indicates how many seconds a cache element should remain before it must be re-retrieved. (default: 1800)
  - <b>structured</b> indicates whether keys will be cached when doing structured encryption and decryption. (default: true)
  - <b>unstructured</b> indicates whether keys will be cached when doing unstructured decryption. (default: true)
  - <b>encrypt</b> indicates if keys should be stored encrypted. If keys are encrypted, they will be harder to access via memory, but require them to be decrypted with each use. (default: false)

   #### IDP specific parameters
  - <b>type</b> indicates the IDP type, either <b>okta</b> or <b>entra</b>
  - <b>customer_id</b> The UUID for this customer.  Will be provided by Ubiq.
  - <b>token_endpoint_url</b> The endpoint needed to authenticate the user credentials, provided by Okta or Entra
  - <b>tenant_id</b> contains the tenant value provided by Okta or Entra
  - <b>client_secret</b> contains the client secret value provided by Okta or Entra

```json
{
  "event_reporting": {
    "wake_interval": 1,
    "minimum_count": 2,
    "flush_interval": 2,
    "trap_exceptions": false,
    "timestamp_granularity" : "NANOS"
  },
  "nodejs" : {
     "lock_sleep_before_retry" : 250,
     "lock_max_retry_count" : 15
  },
  "key_caching" : {
     "structured" : true,
     "unstructured" : true,
     "encrypted" : false,
     "ttl_seconds" : 1800
  },
   "idp": {
    "type": "okta",
    "customer_id": "f6f.....08c5",
    "token_endpoint_url": " https://dev-<domain>.okta.com/oauth2/v1/token",
    "tenant_id": "0o....d7",
    "client_secret": "yro.....2Db"
  }
}
```

## Ubiq API Error Reference

Occasionally, you may encounter issues when interacting with the Ubiq API. 

| Status Code | Meaning | Solution |
|---|---|---|
| 400 | Bad Request | Check name of datasets and credentials are complete. |
| 401 | Authentication issue | Check you have the correct API keys, and it has access to the datasets you are using.  Check dataset name. |
| 426 | Upgrade Required | You are using an out of date version of the library, or are trying to use newer features not supported by the library you are using.  Update the library and try again.
| 429 | Rate Limited | You are performing operations too quickly. Either slow down, or contact support@ubiqsecurity.com to increase your limits. | 
| 500 | Internal Server Error | Something went wrong. Contact support if this persists.  | 
| 504 | Internal Error | Possible API key issue.  Check credentials or contact support.  | 

[dashboard]:https://dashboard.ubiqsecurity.com
[credentials]:https://dev.ubiqsecurity.com/docs/api-keys
[apidocs]:https://dev.ubiqsecurity.com/docs/api
[UbiqSecurityStructuredEncryptDecrypt.test.js]:https://gitlab.com/ubiqsecurity/ubiq-node/-/blob/master/tests/UbiqSecurityStructuredEncryptDecrypt.test.js
[UbiqSampleStructured.js]:https://gitlab.com/ubiqsecurity/ubiq-node/-/blob/master/example/ubiq_sample_structured.js
[configuration]:README.md#L317
