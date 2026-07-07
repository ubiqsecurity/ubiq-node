class Operation {
  /**
   * @param {OperationContext} context
   * @returns {Promise<string>}
   */
  async invokeAsync(context) {
    throw new Error('invoke() must be implemented by subclass');
  }
}

module.exports = Operation;