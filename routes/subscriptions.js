'use strict';

var fs = require('fs');
var path = require('path');
var { debug, info, warn, error } = require('portal-env').Logger('portal-api:subscriptions');
var utils = require('./utils');
var users = require('./users');
var ownerRoles = require('./ownerRoles');
var approvals = require('./approvals');
var webhooks = require('./webhooks');

var subscriptions = require('express').Router();
var dao = require('../dao/dao');
var daoUtils = require('../dao/dao-utils');

const READ_SUBSCRIPTIONS = 'read_subscriptions';
const verifySubscriptionsReadScope = utils.verifyScope(READ_SUBSCRIPTIONS);

// ===== ENDPOINTS =====
subscriptions.get('/', verifySubscriptionsReadScope, function (req, res, next) {
    const { offset, limit } = utils.getOffsetLimit(req);
    const filter = utils.getFilter(req);
    const orderBy = utils.getOrderBy(req);
    const noCountCache = utils.getNoCountCache(req);
    const embed = utils.getEmbed(req);
    subscriptions.getAllSubscriptions(req.app, res, req.apiUserId, filter, orderBy, offset, limit, noCountCache, embed);
});

subscriptions.getAllSubscriptions = function (app, res, loggedInUserId, filter, orderBy, offset, limit, noCountCache, embed) {
    debug('getAllSubscriptions()');
    users.loadUser(app, loggedInUserId, (err, userInfo) => {
        if (err)
            return utils.fail(res, 500, 'getAllSubscriptions: Could not load user.', err);
        if (!userInfo)
            return utils.fail(res, 403, 'Not allowed.');
        if (!userInfo.admin && !userInfo.approver)
            return utils.fail(res, 403, 'Not allowed. This is admin/approver land.');
        if (embed) {
            dao.subscriptions.getAll(filter, orderBy, offset, limit, noCountCache, (err, subsIndex, countResult) => {
                if (err)
                    return utils.fail(res, 500, 'getAllSubscriptions: getAll failed', err);
                res.json({
                    items: subsIndex,
                    count: countResult.count,
                    count_cached: countResult.cached,
                    offset: offset,
                    limit: limit
                });
            });
        } else {
            dao.subscriptions.getIndex(offset, limit, (err, subsIndex, countResult) => {
                if (err)
                    return utils.fail(res, 500, 'getAllSubscriptions: getIndex failed', err);
                res.json({
                    items: subsIndex,
                    count: countResult.count,
                    count_cached: countResult.cached,
                    offset: offset,
                    limit: limit
                });
            });
        }
    });
};

subscriptions.getOwnerRole = function (appInfo, userInfo) {
    debug('getOwnerRole()');
    for (var i = 0; i < appInfo.owners.length; ++i) {
        if (appInfo.owners[i].userId == userInfo.id)
            return appInfo.owners[i].role;
    }
    // Unknown
    return null;
};

subscriptions.getSubscriptions = function (app, res, applications, loggedInUserId, appId) {
    debug('getSubscriptions(): ' + appId);
    dao.applications.getById(appId, (err, appInfo) => {
        if (err)
            return utils.fail(res, 500, 'getSubscriptions: Loading app failed', err);
        if (!appInfo)
            return utils.fail(res, 404, 'Not found: ' + appId);
        users.loadUser(app, loggedInUserId, (err, userInfo) => {
            if (err)
                return utils.fail(res, 500, 'getSubscriptions: loadUser failed.', err);
            if (!userInfo)
                return utils.fail(res, 403, 'Not allowed. User invalid.');

            var isAllowed = false;
            var adminOrCollab = false;
            if (userInfo.admin || userInfo.approver) {
                isAllowed = true;
                adminOrCollab = true;
            }
            if (!isAllowed) {
                // Check for App rights
                var access = subscriptions.getOwnerRole(appInfo, userInfo);
                if (access) // Any role will do for GET
                    isAllowed = true;
                if (ownerRoles.OWNER == access ||
                    ownerRoles.COLLABORATOR == access)
                    adminOrCollab = true;
            }

            if (!isAllowed)
                return utils.fail(res, 403, 'Not allowed. User does not own application.');
            dao.subscriptions.getByAppId(appId, (err, subs) => {
                if (err)
                    return utils.fail(res, 500, 'getSubscriptions: DAO get subscription failed', err);
                for (let i = 0; i < subs.length; ++i)
                    checkScopeSettings(subs[i]);
                // Add some links if admin or collaborator
                if (adminOrCollab) {
                    for (var i = 0; i < subs.length; ++i) {
                        if (!subs[i]._links)
                            subs[i]._links = {};
                        subs[i]._links.deleteSubscription = {
                            href: '/applications/' + appId + '/subscriptions/' + subs[i].api,
                            method: 'DELETE'
                        };
                    }
                }
                return res.json(subs);
            });
        });
    });
};

subscriptions.addSubscription = function (app, res, applications, loggedInUserId, appId, subsCreateInfo) {
    debug('addSubscription(): ' + appId);
    debug(subsCreateInfo);
    dao.applications.getById(appId, (err, appInfo) => {
        if (err)
            return utils.fail(res, 500, 'addSubscription: Loading app failed', err);
        if (!appInfo)
            return utils.fail(res, 404, 'Not found: ' + appId);
        users.loadUser(app, loggedInUserId, (err, userInfo) => {
            if (err)
                return utils.fail(res, '500', 'addSubscription: loadUser failed', err);
            if (!userInfo)
                return utils.fail(res, 403, 'Not allowed. User invalid.');
            if (!userInfo.validated)
                return utils.fail(res, 403, 'Not allowed. Email address not validated.');

            var isAllowed = false;
            var isAdmin = false;
            if (userInfo.admin) {
                isAllowed = true;
                isAdmin = true;
            }
            if (!isAllowed) {
                // Check for App rights
                var access = subscriptions.getOwnerRole(appInfo, userInfo);
                // OWNERs and COLLABORATORs may do this.
                if (access &&
                    ((access == ownerRoles.OWNER) ||
                        (access == ownerRoles.COLLABORATOR)))
                    isAllowed = true;
            }

            if (!isAllowed)
                return utils.fail(res, 403, 'Not allowed. Only owners and collaborators may add a subscription.');

            if (appId != subsCreateInfo.application)
                return utils.fail(res, 400, 'Bad request. App ID in body must match App ID in path.');

            debug('Adding Subscription allowed.');

            var apis = utils.loadApis(app);
            // Valid api name?
            var apiIndex = -1;
            for (let i = 0; i < apis.apis.length; ++i) {
                if (apis.apis[i].id == subsCreateInfo.api) {
                    apiIndex = i;
                    break;
                }
            }
            if (apiIndex < 0)
                return utils.fail(res, 400, 'Bad request. Unknown API "' + subsCreateInfo.api + '".');

            // API deprecated? 
            var selectedApi = apis.apis[apiIndex];
            if (selectedApi.deprecated)
                return utils.fail(res, 400, 'API is deprecated. Subscribing not possible.');

            // Valid plan?
            var foundPlan = false;
            for (let i = 0; i < selectedApi.plans.length; ++i) {
                if (selectedApi.plans[i] == subsCreateInfo.plan) {
                    foundPlan = true;
                    break;
                }
            }
            if (!foundPlan)
                return utils.fail(res, 400, 'Bad request. Invalid plan "' + subsCreateInfo.plan + '".');

            debug('Subscription plan and API known.');

            var apiPlans = utils.loadPlans(app).plans;
            var apiPlanIndex = -1;
            for (let i = 0; i < apiPlans.length; ++i) {
                if (apiPlans[i].id == subsCreateInfo.plan) {
                    apiPlanIndex = i;
                    break;
                }
            }
            if (apiPlanIndex < 0)
                return utils.fail(res, 500, 'Inconsistent API/Plan data. Plan not found: ' + subsCreateInfo.plan);
            var apiPlan = apiPlans[apiPlanIndex];

            // Required group? Or Admin, they may also.
            if (selectedApi.requiredGroup && !selectedApi.partner) {
                // If the user is admin, hasUserGroup will always return true
                let hasGroup = users.hasUserGroup(app, userInfo, selectedApi.requiredGroup);
                if (!hasGroup)
                    return res.status(403).jsonp({ message: 'Not allowed. User does not have access to the API.' });
            }

            // Now check required group for the selected plan
            if (apiPlan.requiredGroup) {
                // If the user is admin, hasUserGroup will always return true
                let hasGroup = users.hasUserGroup(app, userInfo, apiPlan.requiredGroup);
                if (!hasGroup)
                    return utils.fail(res, 403, 'Not allowed. User does not have access to the API Plan.');
            }

            // Is it an oauth2 implicit/authorization code API? If so, the app needs a redirectUri
            if (selectedApi.auth === 'oauth2') {
                // In case the API only has implicit flow or authorization code grant flow,
                // the application NEEDS a redirect URI (otherwise not).
                if (!appInfo.redirectUri &&
                    selectedApi.settings &&
                    !selectedApi.settings.enable_client_credentials &&
                    !selectedApi.settings.enable_password_grant)
                    return utils.fail(res, 400, 'Application does not have a redirectUri');
            }

            dao.subscriptions.getByAppId(appId, (err, appSubs) => {
                if (err)
                    return utils.fail(res, 500, 'addSubscription: DAO load subscriptions failed', err);
                for (var i = 0; i < appSubs.length; ++i) {
                    if (appSubs[i].api == subsCreateInfo.api)
                        return utils.fail(res, 409, 'Application already has a subscription for API "' + subsCreateInfo.api + '".');
                }

                debug('All set to add subscription.');
                debug('Subscription is new.');

                // Is this a request for a trusted application?
                const allowTrusted = isAdmin;
                const wantsTrusted = subsCreateInfo.trusted;
                const isTrusted = allowTrusted && wantsTrusted;

                // Do we need to create an API key? Or did we get one passed in?
                // Or do we require approval? Admins never need approval. A trusted
                // subscription always needs approval, if it's not an Admin creating
                // it.
                var needsApproval = !isAdmin && (apiPlan.needsApproval || wantsTrusted);

                var apiKey = null;
                var clientId = null;
                var clientSecret = null;
                var authMethod = "key-auth";
                if (!needsApproval) {
                    debug('Subscription does not need approval, creating keys.');
                    if (selectedApi.auth && selectedApi.auth.startsWith("oauth2")) { // oauth2
                        clientId = utils.createRandomId();
                        clientSecret = utils.createRandomId();
                        authMethod = selectedApi.auth;
                    } else {
                        // Default to key-auth
                        apiKey = utils.createRandomId();
                        if (subsCreateInfo.apikey)
                            apiKey = subsCreateInfo.apikey;
                    }
                } else {
                    debug('Subscription needs approval.');
                }

                let allowedScopesMode = null;
                let allowedScopes = null;
                // Default scope settings, see https://github.com/Haufe-Lexware/wicked.haufe.io/issues/138
                // Only for OAuth2, of course.
                if (authMethod == 'oauth2') {
                    allowedScopesMode = 'none';
                    allowedScopes = [];
                    // Which flows are allowed? If not only client credentials flow, specify "all"
                    if (selectedApi.settings) {
                        if (selectedApi.settings.enable_authorization_code ||
                            selectedApi.settings.enable_implicit_grant ||
                            selectedApi.settings.enable_password_grant) {
                            allowedScopesMode = 'all';
                        }
                    }
                    // If trusted, then completely trusted. Trusted overrides "allowedScopesMode".
                    if (isTrusted) {
                        allowedScopesMode = 'all';
                    }
                }

                const newSubscription = {
                    id: utils.createRandomId(),
                    application: subsCreateInfo.application,
                    api: subsCreateInfo.api,
                    plan: subsCreateInfo.plan,
                    apikey: apiKey,
                    clientId: clientId,
                    clientSecret: clientSecret,
                    auth: selectedApi.auth,
                    approved: !needsApproval,
                    trusted: isTrusted,
                    changedBy: loggedInUserId,
                    changedDate: utils.getUtc(),
                    _links: {
                        self: { href: '/applications/' + appId + '/subscriptions/' + subsCreateInfo.api },
                        application: { href: '/applications/' + appId },
                        apis: { href: '/apis' },
                        plans: { href: '/plans' }
                    }
                };

                dao.subscriptions.create(newSubscription, loggedInUserId, (err, persistedSubscription) => {
                    if (err)
                        return utils.fail(res, 500, 'addSubscription: DAO create subscription failed', err);

                    // If clientId/Secret are present, include unencrypted in response
                    if (clientId) {
                        persistedSubscription.clientId = clientId;
                        persistedSubscription.clientSecret = clientSecret;
                    }
                    // For returning the subscription, include unencrypted key.
                    if (apiKey) {
                        persistedSubscription.apikey = apiKey;
                    }

                    res.status(201).json(persistedSubscription);

                    // Webhook it, man
                    webhooks.logEvent(app, {
                        action: webhooks.ACTION_ADD,
                        entity: webhooks.ENTITY_SUBSCRIPTION,
                        data: {
                            subscriptionId: persistedSubscription.id,
                            applicationId: appInfo.id,
                            apiId: selectedApi.id,
                            userId: userInfo.id,
                            planId: apiPlan.id
                        }
                    });

                    if (needsApproval) {
                        const approvalInfo = {
                            id: utils.createRandomId(),
                            subscriptionId: persistedSubscription.id,
                            user: {
                                id: userInfo.id,
                                email: userInfo.email,
                            },
                            api: {
                                id: selectedApi.id,
                                name: selectedApi.name,
                                requiredGroup: selectedApi.requiredGroup
                            },
                            application: {
                                id: appInfo.id,
                                name: appInfo.name,
                                trusted: wantsTrusted
                            },
                            plan: {
                                id: apiPlan.id,
                                name: apiPlan.name
                            }
                        };

                        dao.approvals.create(approvalInfo, (err) => {
                            if (err) {
                                // This is very bad. Transaction?
                                error(err);
                            }
                            webhooks.logEvent(app, {
                                action: webhooks.ACTION_ADD,
                                entity: webhooks.ENTITY_APPROVAL,
                                data: {
                                    userId: userInfo.id,
                                    applicationId: appInfo.id,
                                    apiId: selectedApi.id,
                                    planId: apiPlan.id
                                }
                            });
                        });
                    }
                });
            });
        });
    });
};

subscriptions.getSubscription = function (app, res, applications, loggedInUserId, appId, apiId) {
    debug('getSubscription(): ' + appId + ', apiId: ' + apiId);
    dao.applications.getById(appId, (err, appInfo) => {
        if (err)
            return utils.fail(res, 500, 'getSubscription: Loading app failed', err);
        if (!appInfo)
            return utils.fail(res, 404, 'Not found: ' + appId);
        users.loadUser(app, loggedInUserId, (err, userInfo) => {
            if (err)
                return utils.fail(res, 500, 'getSubscription: loadUser failed', err);
            if (!userInfo)
                return utils.fail(res, 403, 'Not allowed. User invalid.');

            var isAllowed = false;
            var adminOrCollab = false;
            if (userInfo.admin) {
                isAllowed = true;
                adminOrCollab = true;
            }
            if (!isAllowed) {
                // Check for App rights
                var access = subscriptions.getOwnerRole(appInfo, userInfo);
                if (access) // Any role will do for GET
                    isAllowed = true;
                if (ownerRoles.OWNER == access ||
                    ownerRoles.COLLABORATOR == access)
                    adminOrCollab = true;
            }
            if (!isAllowed)
                return utils.fail(res, 403, 'Not allowed. User does not own application.');

            dao.subscriptions.getByAppAndApi(appId, apiId, (err, appSub) => {
                if (err)
                    return utils.fail(res, 500, 'getSubscription: Could not get subscription by app and api', err);
                // Did we find it?    
                if (!appSub)
                    return utils.fail(res, 404, 'API subscription not found for application. App: ' + appId + ', API: ' + apiId);

                checkScopeSettings(appSub);

                // var appSub = appSubs[subsIndex];
                if (adminOrCollab) {
                    if (!appSub._links)
                        appSub._links = {};
                    appSub._links.deleteSubscription = {
                        href: '/applications/' + appId + '/subscriptions/' + appSub.api,
                        method: 'DELETE'
                    };
                }

                // Return what we found
                res.json(appSub);
            });
        });
    });
};

function findSubsIndex(appSubs, apiId) {
    var subsIndex = -1;
    for (var i = 0; i < appSubs.length; ++i) {
        if (appSubs[i].api == apiId) {
            subsIndex = i;
            break;
        }
    }
    return subsIndex;
}

function findApprovalIndex(approvalInfos, appId, apiId) {
    var approvalIndex = -1;
    for (var i = 0; i < approvalInfos.length; ++i) {
        var appr = approvalInfos[i];
        if (appr.application.id == appId &&
            appr.api.id == apiId) {
            approvalIndex = i;
            break;
        }
    }
    return approvalIndex;
}

subscriptions.deleteSubscription = function (app, res, applications, loggedInUserId, appId, apiId) {
    debug('deleteSubscription(): ' + appId + ', apiId: ' + apiId);
    dao.applications.getById(appId, (err, appInfo) => {
        if (err)
            return utils.fail(res, 500, 'deleteSubscription: Loading app failed', err);
        if (!appInfo)
            return utils.fail(res, 404, 'Not found: ' + appId);
        users.loadUser(app, loggedInUserId, (err, userInfo) => {
            if (err)
                return utils.fail(res, 500, 'deleteSubscription: loadUser failed', err);
            if (!userInfo)
                return utils.fail(res, 403, 'Not allowed. User invalid.');

            var isAllowed = false;
            if (userInfo.admin || userInfo.approver)
                isAllowed = true;
            if (!isAllowed) {
                // Check for App rights
                var access = subscriptions.getOwnerRole(appInfo, userInfo);
                // OWNERs and COLLABORATORs may do this.
                if (access &&
                    ((access == ownerRoles.OWNER) ||
                        (access == ownerRoles.COLLABORATOR))
                )
                    isAllowed = true;
            }

            if (!isAllowed)
                return utils.fail(res, 403, 'Not allowed. Only owners and collaborators may delete a subscription.');

            dao.subscriptions.getByAppId(appId, (err, appSubs) => {
                if (err)
                    return utils.fail(res, 500, 'deleteSubscription: DAO get subscriptions failed', err);
                var subsIndex = findSubsIndex(appSubs, apiId);
                if (subsIndex < 0)
                    return utils.fail(res, 404, 'Not found. Subscription to API "' + apiId + '" does not exist: ' + appId);

                const subscriptionId = appSubs[subsIndex].id;
                const subscriptionData = appSubs[subsIndex];

                dao.subscriptions.delete(appId, apiId, subscriptionId, (err) => {
                    if (err)
                        return utils.fail(res, 500, 'deleteSubscription: DAO delete subscription failed', err);
                    res.status(204).send('');

                    webhooks.logEvent(app, {
                        action: webhooks.ACTION_DELETE,
                        entity: webhooks.ENTITY_SUBSCRIPTION,
                        data: {
                            subscriptionId: subscriptionId,
                            applicationId: appId,
                            apiId: apiId,
                            userId: loggedInUserId,
                            auth: subscriptionData.auth
                        }
                    });
                });
            });
        });
    });
};

// This is for approving subscriptions
subscriptions.patchSubscription = function (app, res, applications, loggedInUserId, appId, apiId, patchBody) {
    debug('patchSubscription(): ' + appId + ', apiId: ' + apiId);
    debug(patchBody);
    users.loadUser(app, loggedInUserId, (err, userInfo) => {
        if (err)
            return utils.fail(res, 500, 'patchSubscription: loadUser failed', err);
        if (!userInfo)
            return utils.fail(res, 403, 'Not allowed.');
        if (!userInfo.admin && !userInfo.approver)
            return utils.fail(res, 403, 'Not allowed. Only admins and approvers can patch a subscription.');
        dao.subscriptions.getByAppId(appId, (err, appSubs) => {
            if (err)
                return utils.fail(res, 500, 'patchSubscription: DAO load app subscriptions failed', err);
            var subsIndex = findSubsIndex(appSubs, apiId);
            if (subsIndex < 0)
                return utils.fail(res, 404, 'Not found. Subscription to API "' + apiId + '" does not exist: ' + appId);

            let allowPatch = false;
            if (patchBody.approved)
                allowPatch = true;
            if (patchBody.hasOwnProperty('trusted'))
                allowPatch = true;
            let allowScopePatch = false;
            if (userInfo.admin) {
                if (patchBody.hasOwnProperty('allowedScopesMode') ||
                    patchBody.hasOwnProperty('allowedScopes'))
                    allowScopePatch = true;
            }

            if (allowPatch || allowScopePatch) {
                var thisSubs = appSubs[subsIndex];
                // In case a clientId is created, we need to temporary store it here, too,
                // as saveSubscriptions encrypts the ID.
                let tempClientId = null;
                let tempClientSecret = null;
                let tempApiKey = null;

                if (allowPatch && patchBody.approved) {

                    // Now set to approved
                    thisSubs.approved = true;

                    // And generate an apikey
                    if (thisSubs.auth && thisSubs.auth.startsWith("oauth2")) { // oauth2
                        thisSubs.clientId = utils.createRandomId();
                        tempClientId = thisSubs.clientId;
                        thisSubs.clientSecret = utils.createRandomId();
                        tempClientSecret = thisSubs.clientSecret;
                    } else {
                        thisSubs.apikey = utils.createRandomId();
                        tempApiKey = thisSubs.apikey;
                        thisSubs.auth = "key-auth";
                    }
                }

                if (allowPatch && patchBody.hasOwnProperty('trusted')) {
                    // This can go both ways
                    thisSubs.trusted = !!patchBody.trusted;
                }

                if (allowScopePatch) {
                    // Check that this is right
                    if (patchBody.allowedScopesMode) {
                        if (!isValidAllowedScopesMode(patchBody.allowedScopesMode))
                            return utils.fail(res, 400, 'patchSubscription: Invalid allowedScopesMode, must be "all", "none", or "select"');
                        thisSubs.allowedScopesMode = patchBody.allowedScopesMode;
                        if (thisSubs.allowedScopesMode === 'select' && !thisSubs.allowedScopes)
                            thisSubs.allowedScopes = []; // Default, in case not specified
                    }
                    if (patchBody.allowedScopes && thisSubs.allowedScopesMode === 'select') {
                        if (!isValidAllowedScopes(patchBody.allowedScopes))
                            return utils.fail(res, 400, 'patchSubscription: Invalid allowedScopes property, must be array of strings.');
                        thisSubs.allowedScopes = patchBody.allowedScopes;
                    } else if (thisSubs.allowedScopesMode !== 'select') {
                        thisSubs.allowedScopes = [];
                    }
                    if (thisSubs.trusted) {
                        thisSubs.allowedScopesMode = 'all';
                        thisSubs.allowedScopes = [];
                    }
                }

                thisSubs.changedBy = loggedInUserId;
                thisSubs.changedDate = utils.getUtc();
                checkScopeSettings(thisSubs);

                // And persist the subscriptions
                dao.subscriptions.patch(appId, thisSubs, loggedInUserId, (err, updatedSubsInfo) => {
                    if (err)
                        return utils.fail(res, 500, 'patchSubscription: DAO patch subscription failed', err);
                    dao.approvals.deleteByAppAndApi(appId, apiId, (err) => {
                        if (err)
                            return utils.fail(res, 500, 'patchSubscription: DAO delete approvals failed', err);

                        if (tempClientId) {
                            // Replace the ID and Secret for returning, otherwise we'd return the encrypted
                            // strings. We don't want that.
                            updatedSubsInfo.clientId = tempClientId;
                            updatedSubsInfo.clientSecret = tempClientSecret;
                        }
                        // For returning the subscription data, include the unencrypted key.
                        if (tempApiKey) {
                            updatedSubsInfo.apikey = tempApiKey;
                        }


                        res.json(updatedSubsInfo);

                        webhooks.logEvent(app, {
                            action: webhooks.ACTION_UPDATE,
                            entity: webhooks.ENTITY_SUBSCRIPTION,
                            data: {
                                subscriptionId: thisSubs.id,
                                applicationId: appId,
                                apiId: apiId,
                                userId: loggedInUserId
                            }
                        });
                    });
                });
            } else {
                // No-op
                return utils.fail(res, 400, 'Bad request. Patching subscriptions can only be used to approve of subscriptions, or to patch scopes.');
            }
        });
    });
};

function isValidAllowedScopesMode(allowedScopesMode) {
    switch (allowedScopesMode) {
        case 'none':
        case 'all':
        case 'select':
            return true;
    }
    return false;
}

function isValidAllowedScopes(allowedScopes) {
    if (!Array.isArray(allowedScopes)) {
        warn('isValidAllowedScopes: Not an array');
        warn(allowedScopes);
        return false;
    }
    for (let i = 0; i < allowedScopes.length; ++i) {
        if (typeof (allowedScopes[i]) !== 'string') {
            warn('isValidAllowedScopes: One array entry is not a string.');
            warn(allowedScopes);
            return false;
        }
    }
    return true;
}

subscriptions.getSubscriptionByClientId = function (app, res, applications, loggedInUserId, clientId) {
    debug('getSubscriptionByClientId()');
    users.loadUser(app, loggedInUserId, (err, userInfo) => {
        if (err)
            return utils.fail(res, 500, 'getSubscriptionByClientId: loadUser failed', err);
        if (!userInfo)
            return utils.fail(res, 403, 'Not allowed.');
        if (!userInfo.admin)
            return utils.fail(res, 403, 'Not allowed. Only admins may get subscriptions by client ID.');
        dao.subscriptions.getByClientId(clientId, (err, subsInfo) => {
            if (err)
                return utils.fail(res, 500, 'getSubscriptionByClient: DAO failed to load by client id', err);
            if (!subsInfo)
                return utils.fail(res, 404, `Subscription with given client ID ${clientId} was not found.`);
            // Also load the application
            dao.applications.getById(subsInfo.application, (err, appInfo) => {
                if (err)
                    return utils.fail(res, 500, `getSubscriptionByClientId: DAO failed to get application ${subsInfo.application}`, err);
                if (!appInfo) {
                    const errorMessage = 'Inconsistent state. Please notify operator: Application app ' + subsInfo.application + ' not found.';
                    error("getSubscriptionByClientId(): " + errorMessage);
                    return utils.fail(res, 500, errorMessage);
                }

                checkScopeSettings(subsInfo);

                return res.json({
                    subscription: subsInfo,
                    application: appInfo
                });
            });
        });
    });
};

function checkScopeSettings(appSub) {
    debug('checkScopeSettings()');
    console.log(appSub);
    try {
        // Default settings for scopes, see https://github.com/Haufe-Lexware/wicked.haufe.io/issues/138
        if (appSub.auth !== 'oauth2')
            return;
        if (!appSub.allowedScopesMode) {
            appSub.allowedScopesMode = 'none';
            appSub.allowedScopes = [];
            const apiInfo = utils.getApi(appSub.api);
            // For APIs which support other OAuth2 flows than the client credentials flow, the default is "all";
            // usually the resource owner will be asked to grant access anyway, or a trusted subscription is 
            // needed (in case of the resource owner password grant).
            if (apiInfo.settings) {
                if (apiInfo.settings.enable_authorization_code ||
                    apiInfo.settings.enable_implicit_grant ||
                    apiInfo.settings.enable_password_grant) {
                    appSub.allowedScopesMode = 'all';
                    appSub.allowedScopes = [];
                }
            }
            if (appSub.trusted) {
                appSub.allowedScopesMode = 'all';
                appSub.allowedScopes = [];
            }
        }
    } catch (err) {
        error('checkScopeSettings() failed: ' + err.message);
        error(err);
        appSub.allowedScopesMode = 'none';
        appSub.allowedScopes = [];
    }
}


module.exports = subscriptions;
