'use strict';

const { debug, info, warn, error } = require('portal-env').Logger('portal-api:principal');

const dao = require('../dao/dao');
const utils = require('./utils');

const principal = () => { };

const LIVENESS_THRESHOLD = 30; // Seconds
const ELECTION_INTERVAL = 15; // Seconds

let _isPrincipal = false;
let _instanceId = utils.createRandomId();

info(`Creating principal ID for this instance: ${_instanceId}`);

principal.isInstancePrincipal = () => {
    return _isPrincipal;
};

principal.initialElection = () => {
    debug('initialElection()');
    if (!dao.isReady())
        setTimeout(principal.initialElection, 500);
    electPrincipal();
    setInterval(electPrincipal, ELECTION_INTERVAL * 1000);
};

function electPrincipal() {
    debug(`electPrincipal()`);
    if (!dao.isReady()) {
        warn(`DAO is not ready, cannot elect principal.`);
        return;
    }
    dao.meta.getMetadata('principal', function (err, principalInfo) {
        if (err) {
            error('electPrincipal: Could not get metadata!');
            // TODO: Make this instance unhealthy?
            error(err);
            return;
        }

        const nowUtc = utils.getUtc();

        if (principalInfo && (principalInfo.id === _instanceId)) {
            info(`This instance ${_instanceId} is currently the principal instance`);
            // Update the timestamp to reflect that we are alive
            _isPrincipal = true;
            principalInfo.aliveDate = nowUtc;
            dao.meta.setMetadata('principal', principalInfo, (err) => {
                if (err) {
                    error('electPrincipal: Could not update principal aliveDate metadata.');
                    return;
                }
            });
        } else {
            let immediateTimeout = 500;
            if (!principalInfo) {
                principalInfo = { id: null, aliveDate: 0 };
                immediateTimeout = 0;
            }
            debug(`This instance ${_instanceId} is currently not the principal instance (${principalInfo.id})`);
            // Try to make it the current instance?
            const livenessAgeSeconds = nowUtc - principalInfo.aliveDate;
            if (livenessAgeSeconds > LIVENESS_THRESHOLD) {
                debug(`Trying to elect current instance to principal instance (previous instance is stale, ${livenessAgeSeconds}s)`);
                principalInfo.id = _instanceId;
                principalInfo.aliveDate = nowUtc;
                dao.meta.setMetadata('principal', principalInfo, (err) => {
                    if (err) {
                        error('electPrincipal: Could not set principal info metadata.');
                        return;
                    }
                    debug(`electPrincipal: Scheduling new election of principal in ${immediateTimeout}ms.`);
                    setTimeout(electPrincipal, immediateTimeout);
                });
            }
        }
    });
}

module.exports = principal;
