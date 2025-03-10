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

const ubiq = require('ubiq-security');
const { Command } = require('commander');
const pkginfo = require('./package.json');

const program = new Command();

async function main() {
  /*

  Usage: ./src/examples/ubiq_sample_structured -e|-d INPUT -s|-p -n Dataset [-c CREDENTIALS] [-P PROFILE]  [-g CONFIGURATION]
Encrypt or decrypt data using the Ubiq structured datasets
  -h                       Show this help message and exit
  -V                       Show program's version number and exit
  -e INPUT                 Encrypt the supplied input string
                             escape or use quotes if input string
                             contains special characters
  -d INPUT                 Decrypt the supplied input string
                             escape or use quotes if input string
                             contains special characters
  -n Dataset               Use the supplied Field Format Specification
  -c CREDENTIALS           Set the file name with the API credentials
                             (default: ~/.ubiq/credentials)
  -P PROFILE               Identify the profile within the credentials file
  -g CONFIGURATION         Set the file name for loading system configuration parameters
                             (default: ~/.ubiq/configuration)
  */
  program
    .name('ubiq_sample_structured.js')
    .description(`Usage: ubiq_sample_structured.js -e|-d INPUT -s|-b -n Dataset [-c CREDENTIALS] [-P PROFILE] [-g CONFIGURATION]
       Encrypt or decrypt data using the Ubiq structured encryption service`)
    .version(pkginfo.version)
    // .summary(`Usage: ubiq_sample_structured -e|-d INPUT -s|-b -n Dataset [-c CREDENTIALS][-P PROFILE]
    // Encrypt or decrypt data using the Ubiq structured encryption service`)

    .option(
      '-e, --encrypt <input>',
      'Encrypt the supplied input string escape or use quotes if input string',
      null,
    )
    .option(
      '-d, --decrypt <input>',
      'Decrypt the supplied input string escape or use quotes if input string',
      null,
    )
    .option('-n, --dataset <Dataset>', 'Use the supplied dataset name', null)
    .option('-c, --credentials <CREDENTIALS>', 'Set the file name with the API credentials (default: ~/.ubiq/credentials)', null)
    .option('-P, --profile <PROFILE>', 'Identify the profile within the credentials file (default: default', null)
    .option('-g, --config <CONFIGURATION>', 'Set the file name for loading system configuration parameters (default: ~/.ubiq/configuration)', null);

  try {
    program.parse(process.argv);
  } catch (err) {
    console.error(err);
    program.help();
  }
  const options = program.opts();
  if (options.version) {
    console.log(`version: ${pkginfo.version}`);
    process.exit();
  }

  if (!options.encrypt && !options.decrypt) {
    console.log('Please provide a valid option');
    program.help();
    process.exit();
  }
  try {
    const credentials = new ubiq.ConfigCredentials(options.credentials, options.profile);
    const configuration = new ubiq.Configuration(options.config);

    // Test to see if the credentials have been found and loaded properly
    if (credentials.access_key_id === undefined
      || credentials.secret_signing_key === undefined
      || credentials.secret_crypto_access_key === undefined) {
      console.log('  Unable to load credentials file properly.');
      console.log('  Check credentials file pathname and selected profile');
      process.exit();
    }

    // Need to call the credentials init function to make sure the object is setup correctly
    await credentials.initAsync(configuration)

    const tweakFF1 = [];
    if (options.encrypt) {
      const ubiqEncryptDecrypt = new ubiq.structuredEncryptDecrypt.StructuredEncryptDecrypt({ ubiqCredentials: credentials, ubiqConfiguration: configuration });
      const cipherText = await ubiqEncryptDecrypt.EncryptAsync(
        options.dataset,
        options.encrypt,
        tweakFF1,
      );
      console.log(cipherText);
      ubiqEncryptDecrypt.close();
    }
    if (options.decrypt) {
      const ubiqEncryptDecrypt = new ubiq.structuredEncryptDecrypt.StructuredEncryptDecrypt({ ubiqCredentials: credentials, ubiqConfiguration: configuration });
      const plainText = await ubiqEncryptDecrypt.DecryptAsync(
        options.dataset,
        options.decrypt,
        tweakFF1,
      );
      console.log(plainText);
      ubiqEncryptDecrypt.close();
    }
  } catch (err) {
    console.error(err);
    program.help();
  }
}
main();
