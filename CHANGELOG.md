# Changelog

## 2.2.3 - 2025-02-27
* Minor change in the configuration file for IDP support

## 2.2.2 2024-12-13
* Key caching improvement for unstructured decryption
* Key caching options for structured encryption / decryption
* Added support for IDP integration using Okta and Entra


## 2.2.1 2024-08-14
* Updated several package dependencies to new versions
* Key caching improvement for unstructured decryption
* Deprecated simple interfaces for structured encryption
* Incorporated structured encryption submodule directly into this package
* Updated exception handling and updated README documentation
* Updated README code samples



## 2.2.0 2024-05-15
* Support partial encryption rules


## 2.0.2 2023-11-15
* Updated readme for description of configuration data
* Bugfix for loading configuration data
* Adding user-defined billing metadata
* Allow setting billing event timestamp granularity
* Allow read-only fetch of unreported billing events

## 2.0.1 2023-06-12
* Add EncryptForSearch

## 2.0.0 2023-04-21
* Updated default usage configuration values
* Updated library version

## 1.0.10 2023-04-04
* Add trim statement to credentials read from file
* Add code to address improve caching and memory handling in specific conditions

## 1.0.9 2022-11-27
* Fixed some compatibility issues with latest versions of node and updated
  npm libraries.

## 1.0.8 2022-09-22
* Fixed missing named parameters for ubiqCredentials in fpe sample application

## 1.0.7 2022-06-27
* Fixed issue with FPE decrypt with key_number 0

## 1.0.6 2022-06-25
* Added support for Format Preserving Encryption (FPE)
* Added example program for Format Preserving Encryption (FPE)

## 1.0.5 - 2020-02-24
* Added requirement for Node 12 or higher
* Updated copyright notice and comments

## 1.0.4 - 2020-10-28
* Change to MIT license

## 1.0.3 - 2020-10-02
* Updated to use latest version of node-forge library

## 1.0.2 - 2020-09-23
* Remove dead code
* Pass client library name and version to server
* Added AAD information to ciphers for encrypt and decrypt
* Support non-json credentials file

## 1.0.1 - 2020-08-29
* bug fixes loading credentials file and install from source

## 1.0.0 - 2020-08-26
* Initial Version
