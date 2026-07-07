class OperationContext {
  constructor() {
    this.dataset = null;
    this.keyNumber = null;
    this.originalValue = null;
    this.currentValue = null;
    this.isEncrypt = null;
    this.userSuppliedTweak = null;
    this.ffxCache = null;
    this.data = new Map();
  }

  getFfxCache() {
    return this.ffxCache;
  }

  setFfxCache(ffxCache) {
    this.ffxCache = ffxCache;
  }

  getDataset() {
    return this.dataset;
  }

  setDataset(dataset) {
    this.dataset = dataset;
  }

  getKeyNumber() {
    return this.keyNumber;
  }

  setKeyNumber(keyNumber) {
    this.keyNumber = keyNumber;
  }

  getOriginalValue() {
    return this.originalValue;
  }

  setOriginalValue(originalValue) {
    this.originalValue = originalValue;
  }

  getCurrentValue() {
    return this.currentValue;
  }

  setCurrentValue(currentValue) {
    this.currentValue = currentValue;
  }

  getIsEncrypt() {
    return this.isEncrypt;
  }

  setIsEncrypt(isEncrypt) {
    this.isEncrypt = isEncrypt;
  }

  getUserSuppliedTweak() {
    return this.userSuppliedTweak;
  }

  setUserSuppliedTweak(userSuppliedTweak) {
    this.userSuppliedTweak = userSuppliedTweak;
  }

  getData() {
    return this.data;
  }

  setData(data) {
    this.data = data;
  }
}

module.exports = { OperationContext };