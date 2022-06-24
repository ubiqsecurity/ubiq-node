const fetch = require('node-fetch');
const auth = require('./auth');
const { UrlHelper } = require('./urlHelper');

class UbiqWebServices {
    constructor(ubiqCredentials) {
        this.ubiqCredentials = ubiqCredentials;
        this.applicationJson = 'application/json';
        this.endpoint = '/api/v0/encryption/key';
        this.restApiRoot = 'api/v0';
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

        let response;
        try {
            response = await fetch(this.endpoint_base, otherParam);
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
                throw new Error(apiBody.message);
            }
            if (response.status === 401) {
                throw new Error('Unauthorized Request');
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
                return result;
            }
            const apiError = await response.json();
            throw new Error(apiError.message);
        } catch (err) {
            console.error('Error GetFfsConfigurationsync:', err);
            throw err;
        }
    }
}
module.exports = {
    UbiqWebServices,
};
