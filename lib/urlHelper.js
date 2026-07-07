const UrlHelper = {
  GenerateAccessKeyUrl: (credentials) => encodeURIComponent(credentials.access_key_id),

  GenerateFfsUrl: (ffsName, credentials) => `papi=${encodeURIComponent(credentials.access_key_id)}&ffs_name=${encodeURIComponent(ffsName)}`,

  GenerateFpeUrlEncrypt: (ffsName, credentials) => `papi=${encodeURIComponent(credentials.access_key_id)}&ffs_name=${encodeURIComponent(ffsName)}`,

  GenerateFpeUrlDecrypt: (ffsName, keyNumber, credentials) => {
    if (keyNumber === null) {
      throw new Error('invalid or missing key');
    } else {
      return `papi=${encodeURIComponent(credentials.access_key_id)}&ffs_name=${encodeURIComponent(ffsName)}&key_number=${keyNumber}`;
    }
  },

  GenerateDefKeysUrl: (ffsName, credentials) => {
    // ffsName can be string,
    // an empty array,
    // an array with many elements
    // console.log(`ffsName: ${ffsName}`)
    let ret = `papi=${encodeURIComponent(credentials.access_key_id)}`
    // console.log(`GenerateDefKeysUrl: isArray${Array.isArray(ffsName)}`)
    // console.log(`GenerateDefKeysUrl: isArray${Array.isArray(ffsName)}`)
    // console.log(`GenerateDefKeysUrl: !ffsName${!ffsName}`)

    if (Array.isArray(ffsName)) {
      if (ffsName.length > 0) {
        ret += "&ffs_name=" + encodeURIComponent(ffsName.join(','))
        // console.log(`Array.isArray(ffsName) ${ret}`)
      } else {
        // console.log(`empty array ${ret}`)
      }
    } else if (!ffsName) {
      // console.log(`!ffsName ${ret}`)
      // Retrieve all datasets
    } else {
      ret += "&ffs_name=" + encodeURIComponent(ffsName)
      // console.log(`else ${ret}`)
    }
    return ret
  },
};
module.exports = {
  UrlHelper,
};
