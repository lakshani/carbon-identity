/*
 *Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.cache;

import org.wso2.carbon.identity.application.common.cache.BaseCache;
import org.wso2.carbon.identity.application.common.cache.CacheEntry;
import org.wso2.carbon.identity.application.common.cache.CacheKey;

/**
 * This cache keeps all parameters and headers which are directed towards authentication
 * framework. Whenever a request to authentication framework comes, The relevant component which
 * sends the request saves all required information to this cache, which are retrieved later from
 * authentication framework
 */
public class AuthenticationRequestCache extends BaseCache<CacheKey, CacheEntry> {

    private static final String AUTHENTICATION_REQUEST_CACHE_NAME = "AuthenticationRequestCache";
    private static volatile AuthenticationRequestCache instance;

    private AuthenticationRequestCache(String cacheName) {
        super(cacheName);
    }

    private AuthenticationRequestCache(String cacheName, int timeout) {
        super(cacheName, timeout);
    }

    public static AuthenticationRequestCache getInstance(int timeout) {
        if (instance == null) {
            synchronized (AuthenticationRequestCache.class) {
                if (instance == null) {
                    instance = new AuthenticationRequestCache(AUTHENTICATION_REQUEST_CACHE_NAME, timeout);
                }
            }
        }
        return instance;
    }

    public static AuthenticationRequestCache getInstance() {
        if (instance == null) {
            synchronized (AuthenticationRequestCache.class) {
                if (instance == null) {
                    instance = new AuthenticationRequestCache(AUTHENTICATION_REQUEST_CACHE_NAME);
                }
            }
        }
        return instance;
    }
}
