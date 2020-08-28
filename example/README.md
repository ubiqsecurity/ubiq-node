# Ubiq Security Sample Application using Node.js Library


This sample application will demonstrate how to encrypt and decrypt data using the different APIs.


### Documentation

See the [Node.js API docs][apidocs].

## Installation

From within the example directory using [npm] or [yarn]

```sh
cd example
npm install
#or
yarn install
```
## Credentials file

Edit the credentials file with your account [Credentials][credentials] created using the [Ubiq Dashboard][dashboard].

```json
{
  "default": {
    "ACCESS_KEY_ID": "",
    "SECRET_SIGNING_KEY": "",
    "SECRET_CRYPTO_ACCESS_KEY": ""
  }
}
```
## View Program Options

From within the example directory

```
cd example
node ubiq_sample.js -h
```

#### Demonstrate using the simple (-s) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
node ubiq_sample.js -i ./README.md -o /tmp/readme.enc -e -s -c ./credentials.json 
```
#### Demonstrate using the simple (-s) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
node ubiq_sample.js -i /tmp/readme.enc -o /tmp/README.out -d -s -c ./credentials.json
```
#### Demonstrate using the piecewise (-p) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
node ubiq_sample.js -i ./README.md -o /tmp/readme.enc -e -p -c ./credentials.json 
```
#### Demonstrate using the piecewise (-p / --piecewise) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
node ubiq_sample.js -i /tmp/readme.enc -o /tmp/README.out -d -p -c ./credentials.json
```
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[apidocs]:https://dev.ubiqsecurity.com/docs/api
[npm]:https://www.npmjs.com
[dashboard]:https://dev.ubiqsecurity.com/docs/dashboard
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[yarn]: https://yarnpkg.com/