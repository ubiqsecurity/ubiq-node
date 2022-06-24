class Ff1CacheManager {
    constructor() {
        this.map = new Map();
    }

    GetCacheKey(FfsName, KeyNumber) {
        return `${FfsName}-${KeyNumber || 'isNull'}`;
    }

    SetCache(FfsName, KeyNumber, data) {
        const cacheKey = this.GetCacheKey(FfsName, KeyNumber);
        return this.map.set(cacheKey, data);
    }

    GetCache(FfsName, KeyNumber) {
        const cacheKey = this.GetCacheKey(FfsName, KeyNumber);
        if (this.map.has(cacheKey)) {
            return this.map.get(cacheKey);
        }
        return null;
    }
}
module.exports = {
    Ff1CacheManager,
};
