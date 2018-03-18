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
            .get('/hi',   (req, res) => res.send("hello"))
            .get('/info', (req, res) => res.json( { "name": this.commonConfig.application_name, "version": this.commonConfig.application_version, "buildDate": this.commonConfig.build_date } ))

            .all('/secure/*', (req, res, next) => {
                let reqSecureKey = req.header("secure-key"); 
                if(reqSecureKey == null) {
                    reqSecureKey = req.query["secure-key"]; 
                }
                if(security.checkSecureKeyAccess(reqSecureKey, this.config.secureKey)) {
                    next();
                    return;
                }

                const reqAuthorization = req.header("Authorization");
                if(reqAuthorization != null) {
                    const token = reqAuthorization.substring(reqAuthorization.indexOf("Bearer") + 7);
                    if(security.checkJWTAccess(token, this.apiName)) {
                        next();
                        return;
                    }
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