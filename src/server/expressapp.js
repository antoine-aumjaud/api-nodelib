'use strict';

const fs  = require('fs');
const express = require('express');
const jwt = require('jsonwebtoken');

const security = require('../security');

class ExpressApp {
    constructor(commonConfigFile, configFile) {
        this.commonConfig = JSON.parse(fs.readFileSync(commonConfigFile));
        this.config       = JSON.parse(fs.readFileSync(configFile));
    }
    get router() {
        return express.Router()
            .get('/hi',   (req, res) => res.send("hello"))
            .get('/info', (req, res) => res.json( { "name": commonConfig.application_name, "version": commonConfig.application_version, "buildDate": commonConfig.build_date } ))
            
            .all('/secure/*', (req, res, next) => {
                const reqSecureKey = req.header("secure-key"); 
                if(reqSecureKey == null) {
                    reqSecureKey = req.query["secure-key"]; 
                }
                if(security.checkSecureKeyAccess(reqSecureKey, this.config.secureKey)) {
                    next();
                }
                else if(req.header("Authorization") != null) {
                    const header  = req.header("Authorization");
                    const token   = header.substring(header.indexOf("Bearer") + 7);
                    const decoded = security.checkJWTAccess(token);
                    if(decoded != null) {
                        req.header("name",  decoded.name);
                        req.header("login", decoded.login);
                        next();
                    }
                    else {
                        res.status(401).send('Not authorized');
                    }
                }
                else {
                    res.status(401).send('Not authorized');
                }
            }) 

            .get('/secure/reloadConfig', (req, res) => {
                this.config = JSON.parse(fs.readFileSync(configFile));
                res.status(200).send("done");
            })
            ;
    }
}

module.exports = ExpressApp;