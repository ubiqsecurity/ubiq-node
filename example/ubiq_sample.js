// Subject to the foregoing terms and conditions, Ubiq hereby grants to You, at
// no cost, a perpetual, worldwide, non-exclusive, royalty-free, irrevocable
// (except as stated herein) license to the Software, including all right to
// reproduce, prepare derivative works of, sublicense, and distribute the same.
// In the event You institute any litigation, or otherwise make any claim,
// against Ubiq for any reason (including a cross-claim or counterclaim in
// a lawsuit), or violate the terms of this license in any way, this license
// shall terminate automatically, without notice or liability, as of the date
// such litigation is filed or such violation occurs.  This license does not
// grant permission to use Ubiq’s trade names, trademarks, service marks, or
// product names in any way without Ubiq’s express prior written consent.
// THE SOFTWARE IS PROVIDED ON AN “AS IS” BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, WITHOUT
// LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
// MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE. YOU ASSUME ANY
// AND ALL RISKS ASSOCIATED WITH YOUR EXERCISE OF ANY RIGHTS GRANTED HEREUNDER.
// UBIQ SHALL HAVE LIABILITY TO YOU OR TO ANY THIRD PARTIES WITH RESPECT TO
// THIS LICENSE FOR (i) SPECIAL, CONSEQUENTIAL, EXEMPLARY, INCIDENTAL, OR
// PUNITIVE DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOST PROFITS, LOST
// REVENUES, LOST BUSINESS OPPORTUNITIES, LOSS OF USE OR EQUIPMENT DOWNTIME,
// AND LOSS OF OR CORRUPTION TO DATA), REGARDLESS OF THE LEGAL THEORY UNDER
// WHICH THEY ARE SOUGHT (INCLUDING, BUT NOT LIMITED TO ACTIONS FOR BREACH OF
// CONTRACT, NEGLIGENCE, STRICT LIABILITY, RESCISSION AND BREACH OF WARRANTY),
// EVEN IF UBIQ HAD BEEN ADVISED OF, OR SHOULD HAVE FORESEEN, THE POSSIBILITY
// OF SUCH DAMAGES, OR (ii) DIRECT DAMAGES EXCEEDING ONE DOLLAR.  IN NO EVENT
// SHALL UBIQ BE LIABLE FOR COSTS OF PROCUREMENT OF SUBSTITUTE PRODUCTS.
// YOU ACKNOWLEDGE AND AGREE THAT ALL LIMITATIONS AND DISCLAIMERS APPLICABLE
// TO THIS LICENSE ARE ESSENTIAL ELEMENTS OF THIS LICENSE AND THAT THESE
// REFLECT AN EQUITABLE ALLOCATION OF RISK BETWEEN THE PARTIES AND THAT IN
// THEIR ABSENCE THE TERMS OF THIS LICENSE WOULD BE SUBSTANTIALLY DIFFERENT.

const ubiq = require('ubiq-security')

const {argv} = require('yargs')
var fs = require('fs');
const util = require('util');

const credentials_file = argv.c
const input_file = argv.i
var outfile = argv.o
var input_data = ''
var profile = argv.P

// Blocks of 1 MiB
const BLOCK_SIZE = 1024 * 1024

// Allow simple encryption / decryption for files less than 50 MiB
MAX_SIMPLE_SIZE = 1025 * 1024 * 50

var process_mode = ''
var mode = ''

if (argv.V) {
  var pkginfo = require('./package.json')
  console.log(argv.$0 + ": version: " + pkginfo.version)
  return
}



invalid_option = false

if(argv.e){
  process_mode = 'encrypt'
}else if(argv.d){
  process_mode = 'decrypt'
}

if(argv.s){
  mode = 'simple'
}else if(argv.p){
  mode = 'piecewise'
}


if(!process_mode){
  console.log('Please provide a valid option')
  invalid_option = true;
}

if(!mode){
  console.log('Please provide a valid mode')
  invalid_option = true;
}

if(!credentials_file){
  console.log('Credentials File Not Present')
  invalid_option = true;
}

function display_prompt() {
  console.log()
  console.log('usage: ubiq_sample.js [-h] [-V] [-e] [-d] [-s] [-p] -i INFILE -o OUTFILE')
  console.log('                      [-c CREDENTIALS] [-P PROFILE]')
}

function display_help() {
  console.log()
  console.log('  Sample application to provide examples of using the Ubiq Platform Python Client Library')
  console.log()
  console.log('  Created by Ubiq Security, Inc.')
  console.log('  Copyright 2020 Ubiq Security, Inc., All rights reserved.')
  console.log()
  console.log('  Distributed on an "AS IS" basis without warranties')
  console.log('  or conditions of any kind, either express or implied.')
  console.log()
  console.log('USAGE')
  console.log()
  console.log('optional arguments:')
  console.log('  -h             Show this help message and exit')
  console.log('  -V             Show program version number and exit')
  console.log('  -e             Encrypt the contents of the input file and write the')
  console.log('                 results to output file')
  console.log('  -d             Decrypt the contents of the input file and write the')
  console.log('                 results to output file')
  console.log('-s,              Use the simple encryption / decryption interfaces')
  console.log('-p,              Use the piecewise encryption / decryption interfaces')
  console.log('-i INFILE,       Set input file name')
  console.log('-o OUTFILE,      Set output file name')
  console.log('-c CREDENTIALS   Set the file name with the API credentials')
  console.log('                 (default: )~/.ubiq/credentials.json)')
  console.log('  -P PROFILE     Identify the profile within the credentials file')
  console.log('                 (default: default)')
}

if (argv.h) {
  display_prompt()
  display_help()
  return
}

if (invalid_option) {
  display_prompt()
  return
}



let credentials = new ubiq.ConfigCredentials(credentials_file, profile)

const readFile = util.promisify(fs.readFile);

function getStuff(infile) {
  return readFile(infile);
}

async function getData(infile){
  input = await getStuff(infile)
  return input
}

async function simpleEncrypt(){
  input_data = await getData(input_file)
  let encrypted_res = await ubiq.encrypt(credentials, input_data)

  fs.writeFile(outfile, encrypted_res, function (err) {
    if (err) throw err;
  });
}

async function simpleDecrypt(){
  input_data = await getData(input_file)

  let decrypted = await ubiq.decrypt(credentials, input_data)

  let bf = Buffer.from(decrypted, 'binary')

  fs.writeFile(outfile, bf ,function (err) {
    if (err) throw err;
  });
}

async function pieceWiseEncrypt(uses){

  let enc = await new ubiq.Encryption(credentials, uses);
  // This returns the packed byte string
  let begin_res = enc.begin()
  var ws = fs.createWriteStream(outfile, {encoding: 'binary'});
  ws.write(begin_res)
  var readStream = fs.createReadStream(input_file,{ highWaterMark: BLOCK_SIZE  });
  readStream.on('data', function(chunk) {
    res = enc.update(chunk)
    ws.write(res)
  }).on('end', function() {
      // TO indicate all the parsing has been complete
      ws.write(enc.end())
      ws.close()
      enc.close()
    });
}

async function pieceWiseDecrypt(){

  let dec = new ubiq.Decryption(credentials)
  let begin_res = dec.begin()
  var ws = fs.createWriteStream(outfile, {encoding: 'binary'});
  ws.write(begin_res)
  var readStream = fs.createReadStream(input_file,{ highWaterMark: BLOCK_SIZE });
  readStream.on('data', async function(chunk) {
    readStream.pause()
    await dec.update(chunk).then(function(response){
      if(response){
        ws.write(response)
      }
    })
    readStream.resume()
  }).on('end', async function() {
      ws.write(dec.end())
      ws.close()
      dec.close()
  });

}

let stats = fs.statSync(input_file)
var fileSizeInBytes = stats["size"]
if (mode == 'simple' && fileSizeInBytes > MAX_SIMPLE_SIZE) {
	console.log ("NOTE: This is only for demonstration purposes and is designed to work on memory")
    console.log ("      constrained devices.  Therefore, this sample application will switch to")
    console.log ("      the piecewise APIs for files larger than " + MAX_SIMPLE_SIZE + " bytes in order to reduce")
    console.log ("      excesive resource usages on resource constrained IoT devices")
    mode = 'piecewise'
}

if(mode == 'simple'){
  if(process_mode == 'encrypt'){
    simpleEncrypt()
  }else{
    simpleDecrypt()
  }
}else{
  if(process_mode == 'encrypt'){
    pieceWiseEncrypt(1)
  }else{
    pieceWiseDecrypt()
  }
}
