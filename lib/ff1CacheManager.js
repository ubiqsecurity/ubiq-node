class Ff1CacheManager {
  constructor() {
    this.map = new Map();
  }

  GetCacheKey(FfsName, KeyNumber) {
    // KeyNumber 0 was being treated the same as undefined or Null which caused a caching issue.
    let key = `${FfsName}-` + ((KeyNumber === undefined || KeyNumber == null) ? 'isNull' : KeyNumber)

    return key
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
