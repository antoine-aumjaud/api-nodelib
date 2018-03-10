'use strict';

const fs  = require('fs');
const jwt = require('jsonwebtoken');

module.exports.checkSecureKeyAccess = (requestSecureKey, configSecureToken) => {
    if(configSecureToken === requestSecureKey) {
        return true;
    }
    else {
        console.log("SECURITY: error on access to this resource with request secure-key: " + requestSecureKey);
        return false;
    }
}

module.exports.checkJWTAccess = (token) => {
    const cert = fs.readFileSync('conf/jwt-public-cert.pem');  // get public key
    try {
        return jwt.verify(token, cert);
    }
    catch(e) {
        console.log("SECURITY: invalid JWT, " + err);
        return null;
    }
}
