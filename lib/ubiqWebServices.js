const fetch = require('node-fetch');
const auth = require('./auth');
const { UrlHelper } = require('./urlHelper');

class UbiqWebServices {
  constructor(ubiqCredentials) {
    this.ubiqCredentials = ubiqCredentials;
    this.applicationJson = 'application/json';
    this.endpoint = '/api/v0/encryption/key';
    this.restApiRoot = 'api/v0';
    this.restApiV3Root = 'api/v3';
    if (ubiqCredentials.host.indexOf('http') < 0) {
      this.baseUrl = `https://${this.ubiqCredentials.host}`;
    } else {
      this.baseUrl = ubiqCredentials.host;
    }
  }

  async GetFfsConfigurationsync(ffsName) {
    const key = UrlHelper.GenerateFfsUrl(ffsName, this.ubiqCredentials);
    this.endpoint = `/api/v0/ffs?${key}`;
    this.endpoint_base = `${this.baseUrl}${this.endpoint}`;
    const headers = auth.headers(
      this.ubiqCredentials.access_key_id,
      this.ubiqCredentials.secret_signing_key,
      this.endpoint,
      null,
      this.baseUrl,
      'get',
    );
    const otherParam = {
      headers,
      method: 'GET',
    };

    try {
      var response = await fetch(this.endpoint_base, otherParam);
      if (response.status < 400) {
        const result = await response.json();
        return result;
      }
      let validJson = true;
      let apiBody;
      try {
        apiBody = await response.json();
      } catch (err) {
        validJson = false;
      }
      if (validJson && apiBody && apiBody.message) {
        if (apiBody.status) {
          throw new Error(`${apiBody.message}  Status: ${apiBody.status}`);
        } else {
          throw new Error(`${apiBody.message}    Status: ${response.status}`);
        }
      }
      if (response.status === 401) {
        throw new Error(`Unauthorized Request  Status: ${response.status}`);
      }
    } catch (err) {
      if (err.code === 'ENOTFOUND') {
        throw new Error('URL not found.');
      }
      throw err;
    }
  }

  async GetFpeEncryptionKeyAsync(ffsName, keyNumber) {
    let key = '';
    if (keyNumber == null) {
      key = UrlHelper.GenerateFpeUrlEncrypt(ffsName, this.ubiqCredentials);
    } else {
      key = UrlHelper.GenerateFpeUrlDecrypt(ffsName, keyNumber, this.ubiqCredentials);
    }
    this.endpoint = `/${this.restApiRoot}/fpe/key?${key}`;
    this.endpoint_base = `${this.baseUrl}${this.endpoint}`;

    const headers = auth.headers(
      this.ubiqCredentials.access_key_id,
      this.ubiqCredentials.secret_signing_key,
      this.endpoint,
      null,
      this.baseUrl,
      'get',
    );
    const otherParam = {
      headers,
      method: 'GET',
    };
    try {
      const response = await fetch(this.endpoint_base, otherParam);
      if (response.status === 200) {
        const result = await response.json();
        // console.log("GetFpeEncryptionKeyAsync: " + JSON.stringify(result))
        return result;
      }
      const apiError = await response.json();
      throw new Error(apiError.message);
    } catch (err) {
      // console.error('Error GetFfsConfigurationsync:', err);
      throw err;
    }
  }


  // Events is an array of objects, not a string
  async sendBillingAsync(events) {
    // const e = "usage" : [{
    //   datasets: '',
    //   dataset_groups: '',
    //   api_key: '9Rz/BH9C8DFgS45TMKFls52Q',
    //   count: 1,
    //   key_number: 0,
    //   action: 'encrypt',
    //   product: 'ubiq-node',
    //   product_version: '1.0.9',
    //   user_agent: 'ubiq-node/1.0.9',
    //   api_version: 'V3',
    //   date: '2023-03-16T08:18:21.474Z'
    // }]

    // If the array is empty, simply return
    if (typeof (events !== 'undefined') && events.usage) {
      if (events.usage.length == 0) {
        return ""
      }
    }

    this.endpoint = `/${this.restApiV3Root}/tracking/events`;
    this.endpoint_base = `${this.baseUrl}${this.endpoint}`;


    // const url = `http://localhost:8080/api/v3/billing`;
    // Retrieve the necessary headers to make the request using Auth Object
    const headers = auth.headers(
      this.ubiqCredentials.access_key_id,
      this.ubiqCredentials.secret_signing_key,
      this.endpoint,
      events,
      this.baseUrl,
      'post');

    const otherParam = {
      headers,
      body: JSON.stringify(events),
      method: 'POST'
    };

    return new Promise(async (resolve, reject) => {
      try {
        // Wait for server response
        const response = await fetch(this.endpoint_base, otherParam);
        // If response status is success
        if (response.status < 400) {
          // NOP
        }
        // For any other response status code
        else {
          throw new Error(`HTTPError Response: status code: ${response.status}`)
        }
      } catch (ex) {
        reject(ex)
      }
      resolve("");
    });
  }

  async GetFFSAndDataKeys(ffsName) {
    const key = UrlHelper.GenerateFfsUrl(ffsName, this.ubiqCredentials);
    this.endpoint = `/api/v0/fpe/def_keys?${key}`;
    this.endpoint_base = `${this.baseUrl}${this.endpoint}`;
    const headers = auth.headers(
      this.ubiqCredentials.access_key_id,
      this.ubiqCredentials.secret_signing_key,
      this.endpoint,
      null,
      this.baseUrl,
      'get',
    );
    const otherParam = {
      headers,
      method: 'GET',
    };

    let response;
    try {
      response = await fetch(this.endpoint_base, otherParam);
      if (response.status === 200) {
        const result = await response.json();
        return result;
      }
      let validJson = true;
      let apiBody;
      try {
        apiBody = await response.json();
      } catch (err) {
        validJson = false;
      }
      if (validJson && apiBody && apiBody.message) {
        throw new Error(apiBody.message);
      }
      if (response.status === 401) {
        throw new Error(`HTTPError Response: status code: ${response.status}`)
      }
    } catch (err) {
      if (err.code === 'ENOTFOUND') {
        throw new Error('URL not found.');
      }
      throw err;
    }
  }


}
module.exports = {
  UbiqWebServices,
};
