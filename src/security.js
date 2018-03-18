'use strict';

const fs  = require('fs');
const jwtVerifier = require('jsonwebtoken');

module.exports.checkSecureKeyAccess = (requestSecureKey, configSecureToken) => {
    if(configSecureToken === requestSecureKey) {
        return true;
    }
    else {
        console.log("SECURITY: error on access to this resource with request secure-key: " + requestSecureKey);
        return false;
    }
}

module.exports.checkJWTAccess = (token, apiName) => {
    const cert = fs.readFileSync('conf/jwt-public-cert.pem');  // get public key
    try {
        const jwt = jwtVerifier.verify(token, cert);
        if(jwt.autorization == null || (!jwt.autorization.includes("all") && !jwt.autorization.includes(apiName))) {
            console.log("SECURITY: no access, " + jwt.autorization);
            return false;
        } 
        return true;
    }
    catch(e) {
        console.log("SECURITY: invalid JWT, " + e);
        return false;
    }
}
