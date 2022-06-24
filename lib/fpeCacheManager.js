const { UrlHelper } = require('./urlHelper');

class FpeCacheManager {
    constructor(ubiqCredentials, ubiqWebServices) {
        this.map = new Map();
        this.credentials = ubiqCredentials;
        this.ubiqWebServices = ubiqWebServices;
    }

    LoadAsync(ffsName, keyNumber) {
        return this.ubiqWebServices.GetFpeEncryptionKeyAsync(ffsName, keyNumber);
    }

    async GetAsync(FfsName, keyNumber) {
        let url;
        if (keyNumber === null) {
            url = UrlHelper.GenerateFpeUrlEncrypt(FfsName, this.credentials);
        } else {
            url = UrlHelper.GenerateFpeUrlDecrypt(FfsName, keyNumber, this.credentials);
        }
        if (!this.map.has(url)) {
            const fpe = await this.LoadAsync(FfsName, keyNumber);
            if (!fpe) {
                throw new Error(`Could not load Fpe for: ${FfsName}`);
            }
            this.map.set(url, fpe);
        }
        return this.map.get(url);
    }
}
module.exports = {
    FpeCacheManager,
};
