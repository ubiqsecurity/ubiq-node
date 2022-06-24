const { UrlHelper } = require('./urlHelper');

class FfsCacheManager {
    constructor(ubiqCredentials, ubiqWebServices) {
        this.map = new Map();
        this.credentials = ubiqCredentials;
        this.ubiqWebServices = ubiqWebServices;
    }

    LoadAsync(ffsName) {
        return this.ubiqWebServices.GetFfsConfigurationsync(ffsName);
    }

    async GetAsync(FfsName) {
        const url = UrlHelper.GenerateFfsUrl(FfsName, this.credentials);
        if (!this.map.has(url)) {
            const ffs = await this.LoadAsync(FfsName);
            if (!ffs) {
                throw new Error(`Could not load FfsName: ${FfsName}`);
            }
            this.map.set(url, ffs);
        }
        return this.map.get(url);
    }
}
module.exports = {
    FfsCacheManager,
};
