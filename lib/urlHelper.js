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
};
module.exports = {
  UrlHelper,
};
