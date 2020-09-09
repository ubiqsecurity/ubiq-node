// Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains the property
// of Ubiq Security, Inc. The intellectual and technical concepts contained
// herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
// covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this
// information or reproduction of this material is strictly forbidden
// unless prior written permission is obtained from Ubiq Security, Inc.
//
// Your use of the software is expressly conditioned upon the terms
// and conditions available at:
//
//     https://ubiqsecurity.com/legal

const forge = require('node-forge');
// Appends 0 as prefix for values < 10
function formatNo(number){
  if(number < 10){
    return '0' + number
  }else{
    return number
  }
}

// This returns the date time in GMT time zone and in format DayName, Date MonthName Year 10:34:46 GMT
const getDate = function(){
  const monthNames = ["January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
  ];
  const dayNames = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", 'Saturday'];
  gmt_time = new Date().toLocaleString("en-US", {timeZone: "GMT"});
  gmt_date = new Date(gmt_time)
  let month = monthNames[gmt_date.getMonth()].substring(0, 3)
  let day = dayNames[gmt_date.getDay()].substring(0, 3)
  let date = `${day}, ${formatNo(gmt_date.getDate())} ${month} ${gmt_date.getFullYear()} ${formatNo(gmt_date.getHours())}:${formatNo(gmt_date.getMinutes())}:${formatNo(gmt_date.getSeconds())} GMT`
  return date
}

const auth = {
  headers: function(papi, sapi, endpoint, query, host, http_method){
    const Package = require('../package.json')

    // Make the (request-target) value
    let reqt = `${http_method} ${endpoint}`
    let date = new Date();
    let created = parseInt(date.getTime() / 1000);
    // Make the body digest
    var md = forge.md.sha512.create();
    let parsed = JSON.stringify(query)
    md.update(parsed)
    // Finalise the digest
    let sha = forge.util.encode64(md.digest().data)
    let digest = 'SHA-512='+sha
    let all_headers = {}
    all_headers['user-agent'] = 'ubiq-node/'+Package.version
    // The content type of request
    all_headers['content-type'] = 'application/json'
    // The request target calculated above(reqt)
    all_headers['(request-target)'] = reqt
    // The date and time in GMT format
    all_headers['date'] = getDate()
    // The host specified by the caller
    let url = new URL(host);
    all_headers['host'] = url.host
    all_headers['(created)'] = created
    all_headers['digest'] = digest
    let headers = ['content-type', 'date', 'host', '(created)', '(request-target)', 'digest']
    var hmac = forge.hmac.create();
    hmac.start('sha512', sapi);
    for(var i=0; i<headers.length; i++){
      hmac.update(`${headers[i]}: ${all_headers[headers[i]]}\n`)
    }
    delete all_headers['(created)'];
    delete all_headers['(request-target)'];
    delete all_headers['host'];
    all_headers['signature']  = 'keyId="' + papi + '"'
    all_headers['signature'] += ', algorithm="hmac-sha512"'
    all_headers['signature'] += ', created=' + created
    all_headers['signature'] += ', headers="' + headers.join(" ") + '"'
    all_headers['signature'] += ', signature="'
    all_headers['signature'] += forge.util.encode64(hmac.digest().data)
    all_headers['signature'] += '"'
    return all_headers
  }
}

module.exports = auth
