/*
 *  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.saml.servlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.cache.CacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCache;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheKey;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOService;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCache;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.logout.LogoutRequestSender;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.ui.CarbonUIUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * This is the entry point for authentication process in an SSO scenario. This servlet is registered
 * with the URL pattern /samlsso and act as the control servlet. The message flow of an SSO scenario
 * is as follows.
 * <ol>
 * <li>SP sends a SAML Request via HTTP POST to the https://<ip>:<port>/samlsso endpoint.</li>
 * <li>IdP validates the SAML Request and checks whether this user is already authenticated.</li>
 * <li>If the user is authenticated, it will generate a SAML Response and send it back the SP via
 * the samlsso_redirect_ajaxprocessor.jsp.</li>
 * <li>If the user is not authenticated, it will send him to the login page and prompts user to
 * enter his credentials.</li>
 * <li>If these credentials are valid, then the user will be redirected back the SP with a valid
 * SAML Assertion. If not, he will be prompted again for credentials.</li>
 * </ol>
 */
public class SAMLSSOProviderServlet extends HttpServlet {

    private static final long serialVersionUID = -5182312441482721905L;
    private static Log log = LogFactory.getLog(SAMLSSOProviderServlet.class);

    private SAMLSSOService samlSsoService = new SAMLSSOService();

    @Override
    protected void doGet(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse) throws ServletException, IOException {
        handleRequest(httpServletRequest, httpServletResponse, false);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        handleRequest(req, resp, true);
    }

    /**
     * All requests are handled by this handleRequest method. In case of SAMLRequest the user
     * will be redirected to commonAuth servlet for authentication. Based on successful
     * authentication of the user a SAMLResponse is sent back to service provider.
     * In case of logout requests, the IDP will send logout requests
     * to the other session participants and then send the logout response back to the initiator.
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    private void handleRequest(HttpServletRequest req, HttpServletResponse resp, boolean isPost)
            throws ServletException, IOException {
        String sessionId = null;
        Cookie ssoTokenIdCookie = getTokenIdCookie(req);

        if (ssoTokenIdCookie != null){
            sessionId = ssoTokenIdCookie.getValue();
        }

        Cookie rememberMeCookie = getRememberMeCookie(req);
        if (rememberMeCookie != null) {
            sessionId = rememberMeCookie.getValue();
        }

        String queryString = req.getQueryString();
        if (log.isDebugEnabled()) {
            log.debug("Query string : " + queryString);
        }
        // if an openid authentication or password authentication
        String authMode = req.getParameter("authMode");
        if (!SAMLSSOConstants.AuthnModes.OPENID.equals(authMode)) {
            authMode = SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD;
        }
        String relayState = req.getParameter(SAMLSSOConstants.RELAY_STATE);
        String spEntityID = req.getParameter("spEntityID");
        String samlRequest = req.getParameter("SAMLRequest");
        String sessionDataKey = req.getParameter("sessionDataKey");

        try {
            if (sessionDataKey != null) { //Response from common authentication framework.
            	SAMLSSOSessionDTO sessionDTO = getSessionDataFromCache(sessionDataKey);
            	
            	if (sessionDTO != null) {
            		
            		if (sessionDTO.isLogoutReq()) {
            			handleLogoutReponseFromAuthenFramework(req, resp, sessionDTO);
                	} else {
                		sessionId = UUIDGenerator.generateUUID();
    					handleRequestFromLoginPage(req, resp, sessionId, sessionDTO);
                	}
            	} else {
		            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS,
		                    SAMLSSOConstants.Notification.INVALID_MESSAGE_MESSAGE, req, resp);
		            log.error("Failed to retrieve sessionDTO from the cache.");
		            return;
            	}
            } else if (spEntityID != null) { // idp initiated SSO
                handleIdPInitSSO(req, resp, spEntityID, relayState, queryString, authMode, sessionId);
            } else if (samlRequest != null) {// SAMLRequest received. SP initiated SSO
                handleSPInitSSO(req, resp, queryString, relayState, authMode, samlRequest, sessionId, isPost);
            } else {
                log.debug("Invalid request message or single logout message ");
                // Non-SAML request are assumed to be logout requests
                sendToAuthenFrameworkForLogout(req, resp, null, null, sessionId);
                sendNotification(SAMLSSOConstants.Notification.INVALID_MESSAGE_STATUS,
                        SAMLSSOConstants.Notification.INVALID_MESSAGE_MESSAGE, req,
                        resp);
                return;
            }
        } catch (IdentityException e) {
            log.error("Error when processing the authentication request!", e);
            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS
            		,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
        }
    }

    /**
     * Prompts user a notification with the status and message
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    private void sendNotification(String status, String message, HttpServletRequest req,
                                  HttpServletResponse resp) throws ServletException, IOException {
        String redirectURL = CarbonUIUtil.getAdminConsoleURL(req);
        redirectURL = redirectURL.replace("samlsso/carbon/",
                "authenticationendpoint/samlsso_notification.do");
        //TODO Send status codes rather than full messages in the GET request
        String queryParams = "?" + SAMLSSOConstants.STATUS + "=" + status + "&" +
                SAMLSSOConstants.STATUS_MSG + "=" + message;
        resp.sendRedirect(redirectURL + queryParams);
    }

    private void handleIdPInitSSO(HttpServletRequest req, HttpServletResponse resp, String spEntityID, String relayState,
                                  String queryString, String authMode, String sessionId)
            throws IdentityException, IOException, ServletException {

        String rpSessionId = req.getParameter(MultitenantConstants.SSO_AUTH_SESSION_ID);
        SAMLSSOService samlSSOService = new SAMLSSOService();

        SAMLSSOReqValidationResponseDTO signInRespDTO = samlSSOService.validateIdPInitSSORequest(req, resp,
                spEntityID, relayState, queryString, sessionId, rpSessionId, authMode);

        if (signInRespDTO.isValid() && signInRespDTO.getResponse() != null) {
            // user already has an existing SSO session, redirect
            if (SAMLSSOConstants.AuthnModes.OPENID.equals(authMode)) {

                storeRememberMeCookie(sessionId, req, resp, samlSSOService.getSSOSessionTimeout());
            }
            if(samlSSOService.isSAMLSSOLoginAccepted()){
                req.getSession().setAttribute("authenticatedOpenID", SAMLSSOUtil.getOpenID(signInRespDTO.getSubject()));
                req.getSession().setAttribute("openId",SAMLSSOUtil.getOpenID(signInRespDTO.getSubject()));
            }
            sendResponse(req, resp, relayState, signInRespDTO.getResponse(),
                    signInRespDTO.getAssertionConsumerURL(), signInRespDTO.getSubject());
        } else if (signInRespDTO.isValid() && samlSsoService.isOpenIDLoginAccepted() &&
                req.getSession().getAttribute("authenticatedOpenID") != null){
            handleRequestWithOpenIDLogin(req,resp,signInRespDTO,relayState,sessionId);
        } else if (signInRespDTO.isValid() && signInRespDTO.getResponse() == null) {
            // user doesn't have an existing SSO session, so authenticate
            sendToAuthenticate(req, resp, signInRespDTO, relayState);
        } else {
            log.debug("Invalid SAML SSO Request");
            throw new IdentityException("Invalid SAML SSO Request");
        }
    }

    /**
     * If the SAMLRequest is a Logout request then IDP will send logout requests to other session
     * participants and then sends the logout Response back to the initiator. In case of
     * authentication request, check if there is a valid session for the user, if there is, the user
     * will be redirected directly to the Service Provider, if not the user will be redirected to
     * the login page.
     *
     * @param req
     * @param resp
     * @param sessionId
     * @param samlRequest
     * @param relayState
     * @param authMode
     * @throws IdentityException
     * @throws IOException
     * @throws ServletException
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    private void handleSPInitSSO(HttpServletRequest req, HttpServletResponse resp,
                                 String queryString, String relayState, String authMode,
                                 String samlRequest, String sessionId, boolean isPost)
            throws IdentityException, IOException, ServletException {

        String rpSessionId = req.getParameter(MultitenantConstants.SSO_AUTH_SESSION_ID);
        SAMLSSOService samlSSOService = new SAMLSSOService();

        SAMLSSOReqValidationResponseDTO signInRespDTO = samlSSOService.validateSPInitSSORequest(
                samlRequest, queryString, sessionId, rpSessionId, authMode, isPost);
        if (!signInRespDTO.isLogOutReq()) { // an <AuthnRequest> received
        	if (signInRespDTO.isValid() && signInRespDTO.getResponse() != null && !signInRespDTO.isPassive()) {
                // user already has an existing SSO session, redirect
                if (SAMLSSOConstants.AuthnModes.OPENID.equals(authMode)) {

                    storeRememberMeCookie(sessionId, req, resp, samlSSOService.getSSOSessionTimeout());
                }
                if(samlSSOService.isSAMLSSOLoginAccepted()){
                    req.getSession().setAttribute("authenticatedOpenID",SAMLSSOUtil.getOpenID(signInRespDTO.getSubject()));
                    req.getSession().setAttribute("openId",SAMLSSOUtil.getOpenID(signInRespDTO.getSubject()));
                }
                sendResponse(req, resp, relayState, signInRespDTO.getResponse(),
                        signInRespDTO.getAssertionConsumerURL(), signInRespDTO.getSubject());
            } else if (signInRespDTO.isValid() && samlSsoService.isOpenIDLoginAccepted() &&
                    req.getSession().getAttribute("authenticatedOpenID") != null){
                handleRequestWithOpenIDLogin(req,resp,signInRespDTO,relayState,sessionId);
            } else if(signInRespDTO.isValid() && signInRespDTO.getResponse() != null && signInRespDTO.isPassive()){
                sendResponse(req, resp, relayState, signInRespDTO.getResponse(),
                        signInRespDTO.getAssertionConsumerURL(), signInRespDTO.getSubject());
            } else if (signInRespDTO.isValid() && signInRespDTO.getResponse() == null && !signInRespDTO.isPassive()) {
                // user doesn't have an existing SSO session or this is a forceAuthn request, so authenticate
            	removeRememberMeCookie(req, resp);
            	removeTokenIdCookie(req, resp);
                sendToAuthenticate(req, resp, signInRespDTO, relayState);
            } else {
                log.debug("Invalid SAML SSO Request");
                throw new IdentityException("Invalid SAML SSO Request");
            }
        } else { // a <LogoutRequest> received
        	sendToAuthenFrameworkForLogout(req, resp, signInRespDTO, relayState, sessionId);
        }
    }

    /**
     * Sends the user for authentication to the login page
     *
     * @param req
     * @param resp
     * @param signInRespDTO
     * @param relayState
     * @throws ServletException
     * @throws IOException
     */
    private void sendToAuthenticate(HttpServletRequest req, HttpServletResponse resp,
                                    SAMLSSOReqValidationResponseDTO signInRespDTO, String relayState)
            throws ServletException, IOException {

    	
    	
        SAMLSSOSessionDTO sessionDTO = new SAMLSSOSessionDTO();
        sessionDTO.setHttpQueryString(req.getQueryString());
        sessionDTO.setDestination(signInRespDTO.getDestination());
        sessionDTO.setRelayState(relayState);
        sessionDTO.setRequestMessageString(signInRespDTO.getRequestMessageString());
        sessionDTO.setIssuer(signInRespDTO.getIssuer());
        sessionDTO.setRequestID(signInRespDTO.getId());
        sessionDTO.setSubject(signInRespDTO.getSubject());
        sessionDTO.setRelyingPartySessionId(signInRespDTO.getRpSessionId());
        sessionDTO.setAssertionConsumerURL(signInRespDTO.getAssertionConsumerURL());
        sessionDTO.setTenantDomain(req.getParameter("tenantDomain"));
        
        if(signInRespDTO.isIdPInitSSO()) {
            sessionDTO.setIdPInitSSO(true);
        } else {
            sessionDTO.setIdPInitSSO(false);
        }

        String sessionDataKey = UUIDGenerator.generateUUID();
        addSessionDataToCache(sessionDataKey, sessionDTO, req.getSession().getMaxInactiveInterval());

        String commonAuthURL = CarbonUIUtil.getAdminConsoleURL(req);
        commonAuthURL = commonAuthURL.replace("samlsso/carbon/", "commonauth");

        String selfPath = URLEncoder.encode("/samlsso","UTF-8");
        String forceAuthenticate = "false";
        
        if (signInRespDTO.isForceAuthn()) {
        	forceAuthenticate = "true";
        }
        
        String queryParams = "?" + req.getQueryString() + "&relyingParty=" + signInRespDTO.getIssuer() +
                "&" + SAMLSSOConstants.SESSION_DATA_KEY + "=" + sessionDataKey +
                "&type=samlsso" +
                "&commonAuthCallerPath=" + selfPath +
                "&forceAuthenticate=" + forceAuthenticate;
        
        FrameworkUtils.setRequestPathCredentials(req);

        resp.sendRedirect(commonAuthURL + queryParams);
    }
    
    private void sendToAuthenFrameworkForLogout(HttpServletRequest request, HttpServletResponse response, 
    								SAMLSSOReqValidationResponseDTO signInRespDTO, String relayState, String sessionId) 
    										throws ServletException, IOException {
    	
        if (sessionId != null) {
            
            SAMLSSOSessionDTO sessionDTO = new SAMLSSOSessionDTO();
            sessionDTO.setHttpQueryString(request.getQueryString());
            sessionDTO.setRelayState(relayState);
            sessionDTO.setSessionId(sessionId);
            sessionDTO.setLogoutReq(true);
            
            if (signInRespDTO != null) {
            	sessionDTO.setDestination(signInRespDTO.getDestination());
                sessionDTO.setRequestMessageString(signInRespDTO.getRequestMessageString());
                sessionDTO.setIssuer(signInRespDTO.getIssuer());
                sessionDTO.setRequestID(signInRespDTO.getId());
                sessionDTO.setSubject(signInRespDTO.getSubject());
                sessionDTO.setRelyingPartySessionId(signInRespDTO.getRpSessionId());
                sessionDTO.setAssertionConsumerURL(signInRespDTO.getAssertionConsumerURL());
                sessionDTO.setValidationRespDTO(signInRespDTO);
            }
            
        	String sessionDataKey = UUIDGenerator.generateUUID();
        	addSessionDataToCache(sessionDataKey, sessionDTO, request.getSession().getMaxInactiveInterval());

            String commonAuthURL = CarbonUIUtil.getAdminConsoleURL(request);
            commonAuthURL = commonAuthURL.replace("samlsso/carbon/", "commonauth");

            String selfPath = URLEncoder.encode("/samlsso","UTF-8");
            
            SSOSessionPersistenceManager sessionPersistenceManager = SSOSessionPersistenceManager.getPersistenceManager();
            
            String queryParams = "?" + request.getQueryString() +
                    "&" + SAMLSSOConstants.SESSION_DATA_KEY + "=" + sessionDataKey +
                    "&type=samlsso" +
                    "&commonAuthCallerPath=" + selfPath +
                    "&commonAuthLogout=true";
            
            if (signInRespDTO != null) {
            	queryParams = queryParams + "&issuer=" + signInRespDTO.getIssuer();
            }

            response.sendRedirect(commonAuthURL + queryParams);
        }
    }

    /**
     * Sends the Response message back to the Service Provider.
     *
     * @param req
     * @param resp
     * @param relayState
     * @param response
     * @param acUrl
     * @param subject
     * @throws ServletException
     * @throws IOException
     */
    private void sendResponse(HttpServletRequest req, HttpServletResponse resp, String relayState,
                              String response, String acUrl, String subject) throws ServletException, IOException {

        if(relayState != null){
            relayState = URLDecoder.decode(relayState, "UTF-8");
            relayState = relayState.replaceAll("&", "&amp;").replaceAll("\"", "&quot;").replaceAll("'", "&apos;").
                    replaceAll("<", "&lt;").replaceAll(">", "&gt;").replace("\n", "");
        }

        acUrl = getACSUrlWithTenantPartitioning(acUrl, subject);

        PrintWriter out = resp.getWriter();
        out.println("<html>");
        out.println("<body>");
        out.println("<p>You are now redirected back to " + acUrl);
        out.println(" If the redirection fails, please click the post button.</p>");
        out.println("<form method='post' action='" + acUrl + "'>");
        out.println("<p>");
        out.println("<input type='hidden' name='SAMLResponse' value='" + response + "'>");
        out.println("<input type='hidden' name='RelayState' value='" + relayState + "'>");
        out.println("<button type='submit'>POST</button>");
        out.println("</p>");
        out.println("</form>");
        out.println("<script type='text/javascript'>");
        out.println("document.forms[0].submit();");
        out.println("</script>");
        out.println("</body>");
        out.println("</html>");
    }

    /**
     * This method handles authentication and sends authentication Response message back to the
     * Service Provider after successful authentication. In case of authentication failure the user
     * is prompted back for authentication.
     *
     * @param req
     * @param resp
     * @param sessionId
     * @throws IdentityException
     * @throws IOException
     * @throws ServletException
     */
    private void handleRequestFromLoginPage(HttpServletRequest req, HttpServletResponse resp,
                                            String sessionId, SAMLSSOSessionDTO sessionDTO) throws IdentityException, IOException, ServletException {

    	AuthenticationResult authResult = getAuthenticationResultFromCache(req.getParameter("sessionDataKey"));
    	
    	if (authResult == null || !authResult.isAuthenticated() ) {
    		if (log.isDebugEnabled() && authResult != null) {
    			log.debug("Unauthenticated User");
    		}
    		//TODO send a saml response with a status message.
    		sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
    		return;
    	}
    	
    	req.setAttribute(SAMLSSOConstants.AUTHENTICATION_RESULT, authResult);

        String relayState = null;

        if (req.getParameter(SAMLSSOConstants.RELAY_STATE) != null){
            relayState = req.getParameter(SAMLSSOConstants.RELAY_STATE);
        } else {
            relayState = sessionDTO.getRelayState();
        }

        SAMLSSOAuthnReqDTO authnReqDTO = new SAMLSSOAuthnReqDTO();

        populateAuthnReqDTO(req, authnReqDTO, sessionDTO, authResult);
        
        String tenantDomainParam = authnReqDTO.getTenantDomain();
        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        int tenantId = MultitenantConstants.SUPER_TENANT_ID;
        
        if (tenantDomainParam != null && tenantDomainParam.trim().length() > 0) {
        	try {
				tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
			} catch (UserStoreException e) {
				log.error("while getting tenantId from tenantDomain query param", e);
			}
        } 
        
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantId);
        carbonContext.setTenantDomain(tenantDomain);

        SAMLSSOService samlSSOService = new SAMLSSOService();
        SAMLSSORespDTO authRespDTO = samlSSOService.authenticate(authnReqDTO, sessionId, authResult.isAuthenticated(), 
            		authResult.getAuthenticatedAuthenticators(), SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD);
        
        if (authRespDTO.isSessionEstablished()) { // authenticated
            if(req.getParameter("chkRemember") != null && req.getParameter("chkRemember").equals("on")){
                storeRememberMeCookie(sessionId, req, resp, SAMLSSOService.getSSOSessionTimeout());
            }

            storeTokenIdCookie(sessionId, req, resp);

            if(samlSSOService.isSAMLSSOLoginAccepted()){
                req.getSession().setAttribute("authenticatedOpenID",SAMLSSOUtil.getOpenID(authRespDTO.getSubject()));
                req.getSession().setAttribute("openId",SAMLSSOUtil.getOpenID(authRespDTO.getSubject()));
            }
            
            removeSessionDataFromCache(req.getParameter("sessionDataKey"));
            sendResponse(req, resp, relayState, authRespDTO.getRespString(),
                    authRespDTO.getAssertionConsumerURL(), authRespDTO.getSubject());
        } else { // authentication FAILURE
            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
        }
    }
    
    private void handleLogoutReponseFromAuthenFramework(HttpServletRequest request, 
    		HttpServletResponse response, SAMLSSOSessionDTO sessionDTO) 
    					throws ServletException, IOException{
    	
    	SAMLSSOReqValidationResponseDTO validatonResponseDTO = sessionDTO.getValidationRespDTO();
    	
    	if (validatonResponseDTO != null) {
    		// sending LogoutRequests to other session participants
            LogoutRequestSender.getInstance().sendLogoutRequests(validatonResponseDTO.getLogoutRespDTO());
            
            SAMLSSOService samlSSOService = new SAMLSSOService();
            
            if(samlSSOService.isSAMLSSOLoginAccepted()){
            	request.getSession().removeAttribute("authenticatedOpenID");
            	request.getSession().removeAttribute("openId");
            }
            
            SAMLSSOUtil.removeSession(sessionDTO.getSessionId(), validatonResponseDTO.getIssuer());
            
            removeSessionDataFromCache(request.getParameter("sessionDataKey"));
            // sending LogoutResponse back to the initiator
            sendResponse(request, response, sessionDTO.getRelayState(), validatonResponseDTO.getLogoutResponse(),
            		validatonResponseDTO.getAssertionConsumerURL(), validatonResponseDTO.getSubject());
    	} else {
    		try {
				samlSsoService.doSingleLogout(request.getSession().getId());
			} catch (IdentityException e) {
				log.error("Error when processing the logout request!", e);
	            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS,
	                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, request, response);
			}
    		
    		sendNotification(SAMLSSOConstants.Notification.INVALID_MESSAGE_STATUS,
                    SAMLSSOConstants.Notification.INVALID_MESSAGE_MESSAGE, request,
                    response);
    	}
    }

    /**
     *
     * @param req
     * @param authnReqDTO
     */
    private void populateAuthnReqDTO(HttpServletRequest req, SAMLSSOAuthnReqDTO authnReqDTO,
                                     SAMLSSOSessionDTO sessionDTO, AuthenticationResult authResult) {
        authnReqDTO.setAssertionConsumerURL(sessionDTO.getAssertionConsumerURL());
        authnReqDTO.setId(sessionDTO.getRequestID());
        authnReqDTO.setIssuer(sessionDTO.getIssuer());
        authnReqDTO.setSubject(sessionDTO.getSubject());
        authnReqDTO.setRpSessionId(sessionDTO.getRelyingPartySessionId());
        authnReqDTO.setRequestMessageString(sessionDTO.getRequestMessageString());
        authnReqDTO.setQueryString(sessionDTO.getHttpQueryString());
        authnReqDTO.setDestination(sessionDTO.getDestination());
        authnReqDTO.setUsername(authResult.getSubject());
        authnReqDTO.setIdPInitSSO(sessionDTO.isIdPInitSSO());
        authnReqDTO.setUserAttributes(authResult.getUserAttributes());
        authnReqDTO.setClaimMapping(authResult.getClaimMapping());
        authnReqDTO.setTenantDomain(sessionDTO.getTenantDomain());
    }

    /**
     *
     * @param req
     * @return
     */
    private Cookie getRememberMeCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("samlssoRememberMe")) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     *
     * @param sessionId
     * @param req
     * @param resp
     */
    private void storeRememberMeCookie(String sessionId, HttpServletRequest req, HttpServletResponse resp,
                                       int sessionTimeout) {
        Cookie rememberMeCookie = getRememberMeCookie(req);
        if (rememberMeCookie == null) {
            rememberMeCookie = new Cookie("samlssoRememberMe", sessionId);
        }
        rememberMeCookie.setMaxAge(sessionTimeout);
        resp.addCookie(rememberMeCookie);
    }
    
    public void removeRememberMeCookie(HttpServletRequest req, HttpServletResponse resp) {
		
		Cookie[] cookies = req.getCookies();
        if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("samlssoRememberMe")) {
					cookie.setMaxAge(0);
					resp.addCookie(cookie);
					break;
				}
			}
        }
	}

    private Cookie getTokenIdCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("samlssoTokenId")) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     *
     * @param sessionId
     * @param req
     * @param resp
     */
    private void storeTokenIdCookie(String sessionId, HttpServletRequest req, HttpServletResponse resp) {
        Cookie rememberMeCookie = getRememberMeCookie(req);
        if (rememberMeCookie == null) {
            rememberMeCookie = new Cookie("samlssoTokenId", sessionId);
        }
        resp.addCookie(rememberMeCookie);
    }
    
    public void removeTokenIdCookie(HttpServletRequest req, HttpServletResponse resp) {
		
		Cookie[] cookies = req.getCookies();
        if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("samlssoTokenId")) {
					cookie.setMaxAge(0);
					resp.addCookie(cookie);
					break;
				}
			}
        }
	}

    /**
     *
     * @param customLoginPage
     * @return
     */
    private String getLoginPage(String customLoginPage) {
        if (customLoginPage != null && customLoginPage.length() != 0) {
            return "/carbon/" + customLoginPage.trim();
        } else {
            return "authenticationendpoint/" + "samlsso/samlsso_auth_ajaxprocessor.jsp";
        }
    }

    /**
     *
     * @param req
     * @param paramName
     * @return
     */
    private String getRequestParameter(HttpServletRequest req, String paramName) {
        // This is to handle "null" values coming as the parameter values from the JSP.
        if(req.getParameter(paramName) != null && !req.getParameter(paramName).equals("null")){
            return req.getParameter(paramName);
        } else if (req.getAttribute(paramName) != null && !req.getAttribute(paramName).equals("null")) {
            return (String)req.getAttribute(paramName);
        }
        return null;
    }

    private void handleRequestWithOpenIDLogin(HttpServletRequest req, HttpServletResponse resp,
                                              SAMLSSOReqValidationResponseDTO signInRespDTO, String relayState, String sessionId)
            throws ServletException, IOException, IdentityException {

        SAMLSSOSessionDTO sessionDTO = new SAMLSSOSessionDTO();

        sessionDTO.setHttpQueryString(req.getQueryString());
        sessionDTO.setDestination(signInRespDTO.getDestination());
        sessionDTO.setRelayState(relayState);
        sessionDTO.setRequestMessageString(signInRespDTO.getRequestMessageString());
        sessionDTO.setIssuer(signInRespDTO.getIssuer());
        sessionDTO.setRequestID(signInRespDTO.getId());
        sessionDTO.setSubject(signInRespDTO.getSubject());
        sessionDTO.setRelyingPartySessionId(signInRespDTO.getRpSessionId());
        sessionDTO.setAssertionConsumerURL(signInRespDTO.getAssertionConsumerURL());

        String sessionDataKey = UUIDGenerator.generateUUID();
        addSessionDataToCache(sessionDataKey, sessionDTO, req.getSession().getMaxInactiveInterval());

        handleRequestFromLoginPage(req,resp,sessionId, sessionDTO);
    }

    private String getACSUrlWithTenantPartitioning(String acsUrl, String subject) {
        String domain = null;
        String acsUrlWithTenantDomain = acsUrl;
        if (subject != null && MultitenantUtils.getTenantDomain(subject) != null) {
            domain = MultitenantUtils.getTenantDomain(subject);
        }
        if (domain != null &&
                "true".equals(IdentityUtil.getProperty((IdentityConstants.ServerConfig.SSO_TENANT_PARTITIONING_ENABLED)))) {
            acsUrlWithTenantDomain =
                    acsUrlWithTenantDomain + "?" +
                            MultitenantConstants.TENANT_DOMAIN + "=" + domain;
        }
        return acsUrlWithTenantDomain;
    }
    
    private void addSessionDataToCache(String sessionDataKey, SAMLSSOSessionDTO sessionDTO, int cacheTimeout) {
    	SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
    	SessionDataCacheEntry cacheEntry = new SessionDataCacheEntry();
		cacheEntry.setSessionDTO(sessionDTO);
		SessionDataCache.getInstance(cacheTimeout).addToCache(cacheKey, cacheEntry);
    }
    
    private SAMLSSOSessionDTO getSessionDataFromCache(String sessionDataKey) {
    	SAMLSSOSessionDTO sessionDTO = null;
    	SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
		Object cacheEntryObj = SessionDataCache.getInstance(0).getValueFromCache(cacheKey);
		
		if (cacheEntryObj != null) {
			sessionDTO = ((SessionDataCacheEntry)cacheEntryObj).getSessionDTO();
    	}
		
		return sessionDTO;
    }
    
    private void removeSessionDataFromCache(String sessionDataKey) {
    	SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
		SessionDataCache.getInstance(0).clearCacheEntry(cacheKey);
    }
    
    private AuthenticationResult getAuthenticationResultFromCache(String sessionDataKey) {
    	
    	AuthenticationResultCacheKey authResultCacheKey = new AuthenticationResultCacheKey(sessionDataKey);
		CacheEntry cacheEntry = AuthenticationResultCache.getInstance(0).getValueFromCache(authResultCacheKey);
		AuthenticationResult authResult = null;
		
		if (cacheEntry != null) {
			AuthenticationResultCacheEntry authResultCacheEntry = (AuthenticationResultCacheEntry)cacheEntry;
			authResult = authResultCacheEntry.getResult();
		} else {
			log.error("Cannot find AuthenticationResult from the cache");
		}
		
		return authResult;
    }
}
