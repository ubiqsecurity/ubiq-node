const forge = require('node-forge');
const Package = require('../package.json');
// Appends 0 as prefix for values < 10
function formatNo(number) {
  if (number < 10) {
    return `0${number}`;
  }
  return number;
}

// This returns the date time in GMT time zone and in format DayName, Date MonthName Year 10:34:46 GMT
const getDate = () => {
  const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];
  const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const gmtTime = new Date().toLocaleString('en-US', { timeZone: 'GMT' });
  const gmtDate = new Date(gmtTime);
  const month = monthNames[gmtDate.getMonth()].substring(0, 3);
  const day = dayNames[gmtDate.getDay()].substring(0, 3);
  const date = `${day}, ${formatNo(gmtDate.getDate())} ${month} ${gmtDate.getFullYear()} ${formatNo(gmtDate.getHours())}:${formatNo(gmtDate.getMinutes())}:${formatNo(gmtDate.getSeconds())} GMT`;
  return date;
};

const auth = {
  // papi = access key id
  // sapi = SECRET_SIGNING_KEY
  headers(papi, sapi, endpoint, query, host, http_method) {
    // Make the (request-target) value
    const reqt = `${http_method} ${endpoint}`;
    const date = new Date();
    const created = parseInt(date.getTime() / 1000, 10);
    // Make the body digest
    const md = forge.md.sha512.create();
    const parsed = query ? JSON.stringify(query) : '';
    md.update(parsed);
    // Finalise the digest
    const sha = forge.util.encode64(md.digest().data);
    const digest = `SHA-512=${sha}`;
    const allHeaders = {};
    allHeaders['user-agent'] = `ubiq-node/${Package.version}`;
    // The content type of request
    allHeaders['content-type'] = 'application/json';
    // The request target calculated above(reqt)
    allHeaders['(request-target)'] = reqt;
    // The date and time in GMT format
    allHeaders.date = getDate();
    // The host specified by the caller
    const url = new URL(host);
    allHeaders.host = url.host;
    allHeaders['(created)'] = created;
    allHeaders.digest = digest;
    const headers = ['content-type', 'date', 'host', '(created)', '(request-target)', 'digest'];
    const hmac = forge.hmac.create();
    hmac.start('sha512', sapi);
    for (let i = 0; i < headers.length; i++) {
      hmac.update(`${headers[i]}: ${allHeaders[headers[i]]}\n`);
    }
    delete allHeaders['(created)'];
    delete allHeaders['(request-target)'];
    delete allHeaders.host;
    allHeaders.signature = `keyId="${papi}"`;
    allHeaders.signature += ', algorithm="hmac-sha512"';
    allHeaders.signature += `, created=${created}`;
    allHeaders.signature += `, headers="${headers.join(' ')}"`;
    allHeaders.signature += ', signature="';
    allHeaders.signature += forge.util.encode64(hmac.digest().data);
    allHeaders.signature += '"';
    return allHeaders;
  },
};

module.exports = auth;
