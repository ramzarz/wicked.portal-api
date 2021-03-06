'use strict';

var systemhealth = require('./systemhealth');
var users = require('./users');
var utils = require('./utils');

var healthApi = require('express').Router();

// ===== MIDDLEWARE =====

healthApi.use(function (req, res, next) {
    if (!req.get('x-consumer-id'))
        return res.status(403).json({ message: 'Not Allowed.' });
    var customId = req.get('x-consumer-custom-id');
    if (customId) {
        users.loadUser(req.app, customId, (err, userInfo) => {
            if (err)
                return utils.fail(res, 500, 'healthApi: loadUser failed', err);
            if (userInfo)
                return res.status(404).json({ message: 'Not found.' });
            next();
        });
    } else {
        next();
    }
});

// ===== ENDPOINTS =====

healthApi.get('/systemhealth', function (req, res, next) {
    res.json(systemhealth.getSystemHealthInternal(req.app));
});

healthApi.get('/ping', function (req, res, next) {
    res.json({ message: 'OK' });
});

module.exports = healthApi;