// Everything is synchronous

const verbose = false

class ubiqCache {
  constructor(ttl_seconds = 1800) {
    this.ttl_miliseconds = (ttl_seconds === undefined) ? undefined : (ttl_seconds * 1000)
    this.map = new Map()
  }

  set(key, value) {
    let expires = (this.ttl_miliseconds === undefined) ? undefined : Date.now() + this.ttl_miliseconds
    if (verbose) { console.log("cache set ", key, "  expires: ", expires) }
    return this.map.set(key, { value: value, expires: expires })
  }

  get(key) {
    let value = undefined
    let payload = this.map.get(key)
    if (payload) {
      if (verbose) { console.log("cache hit: ", key) }
      if (payload.expires === undefined || payload.expires > Date.now()) {
        if (verbose) { console.log("  cache valid: ") }
        value = payload.value
      } else {
        if (verbose) { console.log("  cache expired: ") }
        this.map.delete(key)
      }
    }
    return value
  }

  // Returns true or false if key existed but don't know if value had expired or not
  delete(key) {
    return this.map.delete(key)
  }

  has(key) {
    return (this.get(key) !== undefined)
  }

  clear(key) {
    this.map.clear()
  }

}


module.exports = {
  ubiqCache,
};
