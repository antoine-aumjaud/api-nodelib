'use strict';

const fs  = require('fs');
const express = require('express');
const jwt = require('jsonwebtoken');

const security = require('../security');

class ExpressApp {
    constructor(apiName) {
        this.apiName      = apiName;
        this.configFile   = 'conf/' + this.apiName + '.json';
        this.commonConfig = JSON.parse(fs.readFileSync('conf-common.json'));
        this.config       = JSON.parse(fs.readFileSync(this.configFile));
    }
    router() {
        return express.Router()
            .use((req, res, next) => { 
                res.header("Access-Control-Allow-Origin", "*"); 
                res.header("Access-Control-Allow-Credentials", "true");
                res.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
                next(); 
            })
            .options('/*',(req, res) => {
                res.header("Access-Control-Max-Age", "86400");
                res.status(200).end()
            })
            .get('/hi',   (req, res) => res.send("hello"))
            .get('/info', (req, res) => res.json( { "name": this.commonConfig.application_name, "version": this.commonConfig.application_version, "buildDate": this.commonConfig.build_date } ))

            .all('/secure/*', (req, res, next) => {
                const configSecureToken = this.config.secureKey

                const reqAuthorization = req.header("Authorization");
                if(reqAuthorization != null) {
                    if(reqAuthorization.startsWith("Basic")) {
                        let reqSecureKeyAuthHeader = Buffer.from(reqAuthorization.substring(6 /* "Basic".length */), 'base64').toString('ascii');
                        reqSecureKeyAuthHeader = reqSecureKeyAuthHeader.substring(0, reqSecureKeyAuthHeader.length - 1);
                        if(security.checkSecureKeyAccess(reqSecureKeyAuthHeader, configSecureToken)) {
                            next();
                            return;
                        }
                    }
                    else if(reqAuthorization.startsWith("Bearer"))  {
                        const token = reqAuthorization.substring(7 /* "Bearer".length */);
                        if(security.checkJWTAccess(token, this.apiName)) {
                            next();
                            return;
                        }
                    }
                }

                const reqSecureKeyHeader = req.header("secure-key"); 
                if(reqSecureKeyHeader != null
                && security.checkSecureKeyAccess(reqSecureKeyHeader, configSecureToken)) {
                    next();
                    return;
                }
                const reqSecureKeyParam = req.query["secure-key"]; 
                if(reqSecureKeyParam != null
                && security.checkSecureKeyAccess(reqSecureKeyParam, configSecureToken)) {
                    next();
                    return;
                }

                res.status(401).send('Not authorized');
            })

            .get('/secure/reloadConfig', (req, res) => {
                this.config = JSON.parse(fs.readFileSync(this.configFile));
                res.status(200).send("done");
            })
            ;
    }
}

module.exports = ExpressApp;