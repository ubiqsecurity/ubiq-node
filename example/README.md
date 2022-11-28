# Ubiq Security Sample Application using Node.js Library


This sample application will demonstrate how to encrypt and decrypt data using the different APIs.


### Documentation

See the [Node.js API docs][apidocs].

## Installation

### Requirements

Node.js version 16 or later
npm version 6 or later

From within the example directory using [npm] or [yarn]

```console
$ cd example
$ npm install
# or
$ yarn install
```
## Credentials file

Edit the credentials file with your account [Credentials][credentials] created using the [Ubiq Dashboard][dashboard].

```sh
[default]
ACCESS_KEY_ID = ...
SECRET_SIGNING_KEY = ...
SECRET_CRYPTO_ACCESS_KEY = ...
```
## View Program Options

From within the example directory

```
$ cd example
$ node ubiq_sample.js -h
```

#### Demonstrate using the simple (-s) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
$ node ubiq_sample.js -i ./README.md -o /tmp/readme.enc -e -s -c ./credentials
```
#### Demonstrate using the simple (-s) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
$ node ubiq_sample.js -i /tmp/readme.enc -o /tmp/README.out -d -s -c ./credentials
```
#### Demonstrate using the piecewise (-p) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
$ node ubiq_sample.js -i ./README.md -o /tmp/readme.enc -e -p -c ./credentials
```
#### Demonstrate using the piecewise (-p / --piecewise) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
$ node ubiq_sample.js -i /tmp/readme.enc -o /tmp/README.out -d -p -c ./credentials
```

This library also incorporates Ubiq Format Preserving Encryption (eFPE).  eFPE allows encrypting so that the output cipher text is in the same format as the original plaintext. This includes preserving special characters and control over what characters are permitted in the cipher text. For example, consider encrypting a social security number '123-45-6789'. The cipher text will maintain the dashes and look something like: 'W$+-qF-oMMV'.


See the [Node.js API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Install or build the library as described [here](/README.md#installation).

## Build the examples
```console
$ cd example
$ npm install
#or
$ yarn install
```
## View Program Options

```console
$ node ./ubiq_sample_fpe.js -h
```

```console
Encrypt or decrypt data using the Ubiq eFPE service

  -h                       Show this help message and exit
  -V                       Show program's version number and exit
  -e INPUT                 Encrypt the supplied input string
                             escape or use quotes if input string
                             contains special characters
  -d INPUT                 Decrypt the supplied input string
                             escape or use quotes if input string
                             contains special characters
  -s                       Use the simple eFPE encryption / decryption interfaces
  -b                       Use the bulk eFPE encryption / decryption interfaces
  -n FFS                   Use the supplied Field Format Specification
  -c CREDENTIALS           Set the file name with the API credentials
                             (default: ~/.ubiq/credentials)
  -P PROFILE               Identify the profile within the credentials file
```
#### Demonstrate encrypting a social security number and returning a cipher text

```console
$ node ./ubiq_sample_fpe.js -c ./credentials -P default -s -n SSN -e 123-45-6789
```
#### Demonstrate decrypting a social security number and returning the plain text

```console
$ node ./ubiq_sample_fpe.js -c ./credentials -P default -s -n SSN -d 400-13-vTQB
```
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[apidocs]:https://dev.ubiqsecurity.com/docs/api
[npm]:https://www.npmjs.com
[dashboard]:https://dev.ubiqsecurity.com/docs/dashboard
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[yarn]: https://yarnpkg.com/
