// ------------------------------------------------------------------------
//
// Copyright 2019 WSO2, Inc. (http://wso2.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// ------------------------------------------------------------------------

import ballerina/config;
import ballerina/http;
import ballerina/log;
import ballerina/time;
import ballerina/mysql;
import ballerina/sql;
import ballerina/cache;
import cellery_hub_api/idp;
import cellery_hub_api/constants;

cache:Cache cache = new(capacity = config:getAsInt(constants:CACHE_CAPACITY_VAR), 
                        expiryTimeMillis = config:getAsInt(constants:CACHE_EXPIRY_VAR));

public type validateRequestFilter object {
    public function filterRequest(http:Caller caller, http:Request request,
    http:FilterContext context) returns boolean {
        log:printDebug("Request was intercepted to validate the token");
        if(request.hasHeader(constants:AUTHENTICATED_USER)) {
            request.removeHeader(constants:AUTHENTICATED_USER);
        }
        string token = "";
        if(request.hasHeader(constants:AUTHORIZATION_HEADER) && request.hasHeader(constants:COOKIE_HEADER)) {
            string tokenHeaderValue = request.getHeader(constants:AUTHORIZATION_HEADER);
            string[] splittedToken = tokenHeaderValue.split(" ");
            if splittedToken.length() != 2 || !(splittedToken[0].equalsIgnoreCase("Bearer")) {
                log:printError("Did not receive the token in proper format");
                return true;
            }
            string lastTokenElement = splittedToken[1];
            string cookieHeader = request.getHeader(constants:COOKIE_HEADER);
            string|error firstTokenElement = getCookie(cookieHeader);
            if (firstTokenElement is error) {
                log:printError("Cookie value could not be resolved. Passing to the next filter", err = firstTokenElement);
                return true;
            } else {
                token = io:sprintf("%s%s", firstTokenElement, lastTokenElement);
                if "" == token {
                    log:printDebug("Did not receive any token. Passing the request to the next filter");
                    return true;
                }
            }
            idp:TokenDetail|error tokenDetail = {
                username: "",
                expiryTime: 0
            };
            if (cache.hasKey(token)) {
                idp:TokenDetail cachedTokenDetail = <idp:TokenDetail>cache.get(token);
                if isExpired(cachedTokenDetail.expiryTime) {
                    log:printError("Token is expired. Passing to the next filter");
                    cache.remove(token);
                    return true;
                } else {
                    request.setHeader(constants:AUTHENTICATED_USER, cachedTokenDetail.username);
                    log:printDebug(io:sprintf("Resolved user as %s from the cache", cachedTokenDetail.username));
                    return true;
                }
            } else {
                tokenDetail = idp:getTokenDetails(untaint token);
            }
            if (tokenDetail is idp:TokenDetail) {
                if (tokenDetail.username != "") {
                    cache.put(token, tokenDetail);
                    request.setHeader(constants:AUTHENTICATED_USER, tokenDetail.username);
                    log:printDebug(io:sprintf("The token is successfully validated for the user %s with expiry time of %d",
                    tokenDetail.username, tokenDetail.expiryTime));
                    return true;
                } else {
                    log:printError("The token is not valid, since the token username is empty");
                    return true;
                }
            } else {
                log:printError("When retrieving the token detail something went wrong", err = tokenDetail);
                return true;
            }
        } else {
            log:printDebug("Did not receive any token. Passing the request to the next filter");
            return true;
        }
    }

    public function filterResponse(http:Response response,
                                   http:FilterContext context)
                                    returns boolean {
        return true;
    }
};

function getCookie(string cookiesString) returns string|error {
    string cookieValue = "";
    string[] cookies = cookiesString.split("\\s*;\\s*");
    foreach string cookie in cookies {
        string[] cookieTokens = cookie.split("=");
        if (cookieTokens[0] == constants:TOKEN_COOKIE_KEY){
            cookieValue = cookieTokens[1];
        }
    }
    if cookieValue == "" {
        CookieNotFoundData errorDetail = {
                        errCookie: cookiesString
        };
        CookieNotFoundError cookieNotFoundError =
                                    error("Cannot find the header Cookie", errorDetail);
        return cookieNotFoundError;
    }
    return cookieValue;
}

type CookieNotFoundData record {
    string errCookie;
};

type CookieNotFoundError error<string, CookieNotFoundData>;

function isExpired(int idpServerTime) returns boolean {
    log:printDebug("Token expiry time will be evaluated");
    time:Time time = time:currentTime();
    log:printDebug(io:sprintf("Adding a skew time of %d", config:getAsInt(constants:SKEW_TIME)));
    int timeNow = time.time;
    if (timeNow/1000 < (idpServerTime + config:getAsInt(constants:SKEW_TIME))) {
        return false;
    } else {
        log:printDebug(io:sprintf("The system time is %d and the expiry time of idp server is %d",
        timeNow/1000, idpServerTime));
        return true;
    }
}
