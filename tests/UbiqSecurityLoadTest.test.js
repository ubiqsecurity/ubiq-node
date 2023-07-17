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

const ubiq = require('../index');
const { Command } = require('commander');
const pkginfo = require('../package.json');

const program = new Command();
const fs = require('fs');

const UBIQ_TEST_DATA_FILE = "UBIQ_TEST_DATA_FILE"
const UBIQ_MAX_AVG_ENCRYPT = "UBIQ_MAX_AVG_ENCRYPT"
const UBIQ_MAX_AVG_DECRYPT = "UBIQ_MAX_AVG_DECRYPT"
const UBIQ_MAX_TOTAL_ENCRYPT = "UBIQ_MAX_TOTAL_ENCRYPT"
const UBIQ_MAX_TOTAL_DECRYPT = "UBIQ_MAX_TOTAL_DECRYPT"

function getEnv(value, key) {
  let ret = (value) ? value : process.env[key]

  // console.log('value:' + value);
  // console.log('key:' + key);
  // console.log('ret:' + ret);

  return ret
}

async function loadTest() {
  /*

  Usage: ./src/examples/ubiq_sample_fpe -e|-d INPUT -s|-p -n FFS [-c CREDENTIALS] [-P PROFILE]
Encrypt or decrypt data using the Ubiq eFPE service
    -h                       Show this help message and exit\n");
    -p                       Print information regarding the failing records.
    -e                       Maximum allowed average encrypt time in microseconds.
                                Not including first call to server
    -d                       Maximum allowed average decrypt time in microseconds.
                                Not including first call to server
    -E                       Maximum allowed total encrypt time in microseconds.
                                Not including first call to server\n");
    -D                       Maximum allowed total decrypt time in microseconds.\n");
                                Not including first call to server\n");
    -i INFILE                Set input file name\n");
    -c CREDENTIALS           Set the file name with the API credentials\n");
                                (default: ~/.ubiq/credentials)\n");
    -P PROFILE               Identify the profile within the credentials file\n");

  */

  // var options = {
  //   credentials: null,
  //   profile: null,
  //   max_avg_encrypt: null,
  //   max_avg_decrypt: null,
  //   max_total_encrypt: null,
  //   max_total_decrypt: null,
  //   input: null
  // }

  var failed = false

  program
    .name('load_test.js')
    .description(`Usage: load_test.js [-e max_avg_encrypt] [-d max_acg_decrypt] [-E max_total_encrypt] [-D max_total_decrypt] -i INPUT [-c CREDENTIALS] [-P PROFILE]
       Run performance tests and validate the cross language compatibility`)
    .version(pkginfo.version)
    .option(
      '-p, --print_errors',
      'Print information regarding data validation errors',
      false,
    )
    .option(
      '-e, --max_avg_encrypt <value>',
      'Maximum allowed average encrypt time in microseconds',
      0,
    )
    .option(
      '-d, --max_avg_decrypt <value>',
      'Maximum allowed average decrypt time in microseconds',
      0,
    )
    .option(
      '-E, --max_total_encrypt <value>',
      'Maximum allowed total encrypt time in microseconds',
      0,
    )
    .option(
      '-D, --max_total_decrypt <value>',
      'Maximum allowed total decrypt time in microseconds',
      0,
    )
    .option(
      '-i, --input <input>',
      'Name of the input datafile in json format',
      null,
    )
    .option('-c, --credentials <CREDENTIALS>', 'Set the file name with the API credentials (default: ~/.ubiq/credentials)', null)
    .option('-P, --profile <PROFILE>', 'Identify the profile within the credentials file (default: default', null);

  try {
    program.parse(process.argv);
  } catch (err) {
    console.error(err);
    program.help();
  }
  const options = program.opts();
  if (options.version) {
    console.log(`version: ${pkginfo.version}`);
    return true
  }

  options.input = getEnv(options.input, UBIQ_TEST_DATA_FILE)
  options.max_avg_encrypt = getEnv(options.max_avg_encrypt, UBIQ_MAX_AVG_ENCRYPT)
  options.max_avg_decrypt = getEnv(options.max_avg_decrypt, UBIQ_MAX_AVG_DECRYPT)
  options.max_total_encrypt = getEnv(options.max_total_encrypt, UBIQ_MAX_TOTAL_ENCRYPT)
  options.max_total_decrypt = getEnv(options.max_total_decrypt, UBIQ_MAX_TOTAL_DECRYPT)

  if (!options.input) {
    console.log('Please provide a valid input file:' + options.input);
    return true
  }

  try {
    credentials = null

    if (options.credentials) {
      credentials = new ubiq.ConfigCredentials(options.credentials, options.profile);
    } else {
      credentials = new ubiq.Credentials(null, null, null, null)
    }

    // Test to see if the credentials have been found and loaded properly
    if (credentials.access_key_id === undefined
      || credentials.secret_signing_key === undefined
      || credentials.secret_crypto_access_key === undefined) {
      console.log('  Unable to load credentials file properly.');
      console.log('  Check credentials file pathname and selected profile');
      return true
    }

    let rawdata = fs.readFileSync(options.input);
    let dataArray = JSON.parse(rawdata);

    let count = dataArray.length;

    const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials: credentials });
    const tweakFF1 = [];

    var perf_times = new Map();
    var errors = new Array();

    for (let l = 0; l < count; l++) {
      let obj = dataArray[l]

      if (l % 1000 == 0) {
        console.log("Processing record: " + l)
      }

      // First call seed
      if (!perf_times.has(obj.dataset)) {
        let tmp = await ubiqEncryptDecrypt.EncryptAsync(
          obj.dataset,
          obj.plaintext,
          tweakFF1,
        );
        tmp = await ubiqEncryptDecrypt.DecryptAsync(
          obj.dataset,
          obj.ciphertext,
          tweakFF1,
        );

        perf_times.set(obj.dataset, {
          encrypt_duration: 0,
          decrypt_duration: 0,
          recordCount: 0
        })

      }

      let s = process.hrtime();

      const ct = await ubiqEncryptDecrypt.EncryptAsync(
        obj.dataset,
        obj.plaintext,
        tweakFF1,
      );

      let e = process.hrtime();
      const pt = await ubiqEncryptDecrypt.DecryptAsync(
        obj.dataset,
        obj.ciphertext,
        tweakFF1,
      );

      let d = process.hrtime();


      if (ct != obj.ciphertext || pt != obj.plaintext) {
        errors.push({ dataset: obj.dataset, plaintext: obj.plaintext })
      }


      let x = perf_times.get(obj.dataset)
      x.recordCount += 1;
      x.encrypt_duration += (e[0] * 1000000000 + e[1]) - (s[0] * 1000000000 + s[1]);
      x.decrypt_duration += (d[0] * 1000000000 + d[1]) - (e[0] * 1000000000 + e[1]);
      perf_times.set(obj.dataset, x);

    }
    ubiqEncryptDecrypt.close();

    var total = {
      encrypt_duration: 0,
      decrypt_duration: 0,
    };

    failed = (errors.length != 0)

    if (errors.length == 0) {
      console.log("All data validated")

      console.log("Encrypt records count " + count + ".  Times in (microseconds)")
      for (var entry of perf_times.entries()) {
        total.encrypt_duration += entry[1].encrypt_duration;
        entry[1].encrypt_duration = Math.round(entry[1].encrypt_duration /= 1000);
        console.log("\tDataset: " + entry[0] + ", record_count: " + entry[1].recordCount + ", Average: " + Math.round(entry[1].encrypt_duration / entry[1].recordCount) + ", total " + entry[1].encrypt_duration)
      }
      total.encrypt_duration = Math.round(total.encrypt_duration / 1000);
      console.log("\t  Total: Average: " + Math.round(total.encrypt_duration / count) + ", total " + total.encrypt_duration)

      console.log("\nDecrypt records count " + count + ".  Times in (microseconds)")
      for (var entry of perf_times.entries()) {
        total.decrypt_duration += entry[1].decrypt_duration;
        entry[1].decrypt_duration = Math.round(entry[1].decrypt_duration / 1000)
        console.log("\tDataset: " + entry[0] + ", record_count: " + entry[1].recordCount + ", Average: " + Math.round(entry[1].decrypt_duration / entry[1].recordCount) + ", total " + entry[1].decrypt_duration)
      }
      total.decrypt_duration = Math.round(total.decrypt_duration /= 1000);

      console.log("\t  Total: Average: " + Math.round(total.decrypt_duration / count) + ", total " + total.decrypt_duration)

      if (options.max_avg_encrypt > 0) {
        if (options.max_avg_encrypt <= Math.round(total.encrypt_duration / count)) {
          failed = true
          console.error("FAILED: Exceeded maximum allowed average encrypt threshold of " + options.max_avg_encrypt + " microseconds")
        } else {
          console.log("PASSED: Maximum allowed average encrypt threshold of " + options.max_avg_encrypt + " microseconds")
        }
      } else {
        console.log("NOTE: No Maximum allowed average encrypt threshold supplied")
      }

      if (options.max_avg_decrypt > 0) {
        if (options.max_avg_decrypt <= Math.round(total.decrypt_duration / count)) {
          failed = true
          console.error("FAILED: Exceeded maximum allowed average decrypt threshold of " + options.max_avg_decrypt + " microseconds")
        } else {
          console.log("PASSED: Maximum allowed average decrypt threshold of " + options.max_avg_decrypt + " microseconds")
        }
      } else {
        console.log("NOTE: No Maximum allowed average decrypt threshold supplied")
      }

      if (options.max_total_encrypt > 0) {
        if (options.max_total_encrypt <= Math.round(total.encrypt_duration)) {
          failed = true
          console.error("FAILED: Exceeded maximum allowed total encrypt threshold of " + options.max_total_encrypt + " microseconds")
        } else {
          console.log("PASSED: Maximum allowed total encrypt threshold of " + options.max_total_encrypt + " microseconds")
        }
      } else {
        console.log("NOTE: No Maximum allowed total encrypt threshold supplied")
      }

      if (options.max_total_decrypt > 0) {
        if (options.max_total_decrypt <= Math.round(total.decrypt_duration)) {
          failed = true
          console.error("FAILED: Exceeded maximum allowed total decrypt threshold of " + options.max_total_decrypt + " microseconds")
        } else {
          console.log("PASSED: Maximum allowed total decrypt threshold of " + options.max_total_decrypt + " microseconds")
        }
      } else {
        console.log("NOTE: No Maximum allowed total decrypt threshold supplied")
      }
    } else {
      console.error("ERROR: Encrypt / Decrypt operation failed to validate for " + errors.length + " record(s)")
      if (!options.print_errors) {
        console.error("       use -p option to print information about records that failed validation")
      } else {
        for (let l = 0; l < errors.length; l++) {
          console.error("  dataset: '" + errors[l].dataset + "'  plaintext: '" + errors[l].plaintext + "'")
        }
      }
    }


  } catch (err) {
    failed = true
    console.error(err);
  }
  return failed
}

test('LoadTest', async () => {
  expect(await loadTest()).toBe(false)
});
