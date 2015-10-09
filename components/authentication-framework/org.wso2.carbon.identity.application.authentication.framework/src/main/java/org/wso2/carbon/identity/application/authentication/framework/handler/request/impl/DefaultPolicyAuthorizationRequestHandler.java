package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PolicyAuthorizationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.CharacterEncoder;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtDBQueries;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.ui.EntitlementPolicyConstants;
import org.wso2.carbon.identity.entitlement.ui.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.ui.dto.RowDTO;
import org.wso2.carbon.identity.entitlement.ui.util.PolicyCreatorUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DefaultPolicyAuthorizationRequestHandler implements PolicyAuthorizationRequestHandler {
    private static final Log log = LogFactory.getLog(DefaultPolicyAuthorizationRequestHandler.class);
    private static volatile DefaultPolicyAuthorizationRequestHandler instance;

    public static DefaultPolicyAuthorizationRequestHandler getInstance() {

        if (instance == null) {
            synchronized (DefaultPolicyAuthorizationRequestHandler.class) {
                if (instance == null) {
                    instance = new DefaultPolicyAuthorizationRequestHandler();
                }
            }
        }
        return instance;
    }

    /**
     * Executes the authentication flow
     *
     * @param request  request
     * @param response response
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            log.debug("In policy authorization flow...");
        }

        boolean isPolicyAdded = false;
        String tenantResourceName = "";
        String idpResourceName = "";

        if (context != null) {
            SequenceConfig sequenceConfig = context.getSequenceConfig();
            if (sequenceConfig != null) {
                String spName = context.getServiceProviderName();
                String tenantName = context.getTenantDomain();
                if (sequenceConfig.getStepMap() != null) {
                    StepConfig idp = sequenceConfig.getStepMap().get(1);
                    String idpName = idp.getAuthenticatedIdP();
                    String authenticatorName = "";
                    if (idp.getAuthenticatedAutenticator() != null) {
                        authenticatorName = idp.getAuthenticatedAutenticator().getName();
                    }
                    isPolicyAdded = GetPolicyAddingStatus(spName, tenantName, idpName, authenticatorName);
                    tenantResourceName = spName + "@" + tenantName;
                    idpResourceName = idpName + "@" + tenantName;
                }
            }

            if (isPolicyAdded) {
                List<RowDTO> rowDTOs = new ArrayList<RowDTO>();

                RowDTO rowDTOTenant = new RowDTO();
                rowDTOTenant.setAttributeValue(tenantResourceName);
                rowDTOTenant.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
                rowDTOTenant.setAttributeId("urn:oasis:names:tc:xacml:1.0:resource:tenant-id");
                rowDTOTenant.setCategory("urn:oasis:names:tc:xacml:3.0:attribute-category:tenant");
                rowDTOs.add(rowDTOTenant);

                RowDTO rowDTOResource = new RowDTO();
                rowDTOResource.setAttributeValue(idpResourceName);
                rowDTOResource.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
                rowDTOResource.setAttributeId("urn:oasis:names:tc:xacml:1.0:resource:idp-id");
                rowDTOResource.setCategory("urn:oasis:names:tc:xacml:3.0:attribute-category:idp");
                rowDTOs.add(rowDTOResource);

                Map<ClaimMapping, String> claimValuesMap = context.getSubject().getUserAttributes();
                ClaimMapping[] claimMappingArray = context.getExternalIdP().getClaimMappings();

                if (sequenceConfig != null) {
                    try {
                        ApplicationConfig applicationConfig = sequenceConfig.getApplicationConfig();
                        if (applicationConfig != null) {
                            Map<String, String> requiredClaimMap = applicationConfig.getRequestedClaimMappings();
                            for (Map.Entry<String, String> entry : requiredClaimMap.entrySet()) {
                                String requiredClaim = entry.getKey();
                                ClaimsUrlValuesMap claimUrlValuesMap = getClaimsValuesByRequiredClaim(requiredClaim, claimValuesMap, claimMappingArray);
                                if (claimUrlValuesMap != null) {
                                    String claimValue = CharacterEncoder.getSafeText(claimUrlValuesMap.getClaimValue());
                                    String category = "urn:oasis:names:tc:xacml:3.0:attribute-category:".concat(claimUrlValuesMap.getRemoteClaimUrl());
                                    RowDTO rowDTO = new RowDTO();
                                    rowDTO.setAttributeValue(claimValue);
                                    rowDTO.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
                                    rowDTO.setAttributeId(requiredClaim);
                                    rowDTO.setCategory(category);
                                    rowDTOs.add(rowDTO);
                                }
                            }

                            RequestDTO requestDTO = new RequestDTO();
                            requestDTO.setRowDTOs(rowDTOs);
                            RequestElementDTO requestElementDTO = PolicyCreatorUtil.createRequestElementDTO(requestDTO);

                            String requestString = PolicyBuilder.getInstance().buildRequest(requestElementDTO);
                            String decisionValue = FrameworkServiceDataHolder.getInstance().getEntitlementService().getDecision(requestString);
                            Boolean isAuthorized = evaluateDecision(decisionValue);
                            if (!isAuthorized) {
                                context.setRequestAuthenticated(false);
                                context.getSequenceConfig().setCompleted(true);
                            }
                            if (log.isDebugEnabled()) {
                                log.info("User authorization status: " + decisionValue);
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        log.error("Error occurred while authorization flow", e);
                    }
                }
            }
        }
    }

    private Boolean evaluateDecision(String decisionValue) {
        try {
            DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            InputSource is = new InputSource();
            is.setCharacterStream(new StringReader(decisionValue));
            Document doc = db.parse(is);
            Element rootElement = doc.getDocumentElement();
            NodeList nodelist = rootElement.getChildNodes();
            Node node;

            for (int i = 0; i < nodelist.getLength(); i++) {
                node = nodelist.item(i);
                if (node.getNodeName().equals("Decision")) {
                    String nodeValue = node.getNodeValue();
                    if (nodeValue.equalsIgnoreCase("Permit") || nodeValue.equalsIgnoreCase("Not Applicable")) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error occurred while parsing XACML response", e);
        }
        return false;
    }

    private ClaimsUrlValuesMap getClaimsValuesByRequiredClaim(String requiredClaim,
                                                              Map<ClaimMapping, String> claimValuesMap,
                                                              ClaimMapping[] claimMappingArray) {
        String remoteClaimName;
        ClaimsUrlValuesMap claimsUrlValuesMap;
        for (ClaimMapping aClaimMappingArray : claimMappingArray) {
            String localClaimUrl = aClaimMappingArray.getLocalClaim().getClaimUri();
            if (localClaimUrl.equals(requiredClaim)) {
                remoteClaimName = aClaimMappingArray.getRemoteClaim().getClaimUri();

                for (Map.Entry<ClaimMapping, String> entry : claimValuesMap.entrySet()) {
                    ClaimMapping entryMap = entry.getKey();

                    if (entryMap.getRemoteClaim().getClaimUri().equals(remoteClaimName)) {
                        claimsUrlValuesMap = new ClaimsUrlValuesMap(localClaimUrl, remoteClaimName, entry.getValue());
                        return claimsUrlValuesMap;
                    }
                }
            }
        }
        return null;
    }


    private boolean GetPolicyAddingStatus(String spName, String tenantName, String idpName, String authenticatorName) {
        boolean isPolicyAdded = false;

        try {
            int tenantId = FrameworkServiceComponent.getRealmService().getTenantManager()
                    .getTenantId(tenantName);
            Connection connection = IdentityDatabaseUtil.getDBConnection();
            int authenticatorId = getAuthenticatorID(connection, tenantId, idpName, authenticatorName);

            int spId = getApplicationIDByName(spName, tenantId, connection);
            isPolicyAdded = getPolicyAddedForSPAndAuthenticator(spId, authenticatorId, connection);
        } catch (Exception e) {
            log.error("Error occurred while getting policy availability.", e);
        }
        return isPolicyAdded;
    }

    private int getAuthenticatorID(Connection conn, int tenantId, String idpName,
                                   String authenticatorName) throws SQLException {
        if (idpName == null || idpName.isEmpty()) {
            return -1;
        }
        int authId = -1;

        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        String sqlStmt = ApplicationMgtDBQueries.LOAD_IDP_AUTHENTICATOR_ID;
        try {
            prepStmt = conn.prepareStatement(sqlStmt);
            prepStmt.setString(1, CharacterEncoder.getSafeText(authenticatorName));
            prepStmt.setString(2, CharacterEncoder.getSafeText(idpName));
            prepStmt.setInt(3, tenantId);
            prepStmt.setInt(4, tenantId);
            prepStmt.setInt(5, MultitenantConstants.SUPER_TENANT_ID);
            rs = prepStmt.executeQuery();
            if (rs.next()) {
                authId = rs.getInt(1);
            }
        } finally {
            IdentityApplicationManagementUtil.closeStatement(prepStmt);
            IdentityApplicationManagementUtil.closeResultSet(rs);
            IdentityApplicationManagementUtil.closeConnection(conn);
        }
        return authId;
    }

    private int getApplicationIDByName(String applicationName, int tenantID, Connection connection)
            throws IdentityApplicationManagementException {

        int applicationId = 0;
        PreparedStatement getAppIDPrepStmt = null;
        ResultSet appidResult = null;

        try {
            getAppIDPrepStmt = connection
                    .prepareStatement(ApplicationMgtDBQueries.LOAD_APP_ID_BY_APP_NAME);
            getAppIDPrepStmt.setString(1, CharacterEncoder.getSafeText(applicationName));
            getAppIDPrepStmt.setInt(2, tenantID);
            appidResult = getAppIDPrepStmt.executeQuery();

            if (!connection.getAutoCommit()) {
                connection.commit();
            }

            if (appidResult.next()) {
                applicationId = appidResult.getInt(1);
            }

        } catch (SQLException e) {
            log.error("Error occurred while getting application ID", e);
            throw new IdentityApplicationManagementException("Error occurred while getting application ID", e);
        } finally {
            IdentityApplicationManagementUtil.closeResultSet(appidResult);
            IdentityApplicationManagementUtil.closeStatement(getAppIDPrepStmt);
            IdentityApplicationManagementUtil.closeConnection(connection);
        }

        return applicationId;
    }

    private boolean getPolicyAddedForSPAndAuthenticator(
            int applicationId, int authenticatorId, Connection connection) throws SQLException {
        PreparedStatement getPolicyInfoPrepStmt = null;
        ResultSet stepInfoResultSet = null;
        boolean isPolicyAdded;
        try {
            getPolicyInfoPrepStmt = connection
                    .prepareStatement(ApplicationMgtDBQueries.LOAD_POLICY_ADDED_INFO_BY_APP_ID_AND_AUTHENTICATOR_ID);
            getPolicyInfoPrepStmt.setInt(1, applicationId);
            getPolicyInfoPrepStmt.setInt(2, authenticatorId);
            stepInfoResultSet = getPolicyInfoPrepStmt.executeQuery();

            if (stepInfoResultSet.next()) {
                isPolicyAdded = stepInfoResultSet.getInt(1) == 1;
                return isPolicyAdded;
            }
            return false;
        } finally {
            IdentityApplicationManagementUtil.closeStatement(getPolicyInfoPrepStmt);
            IdentityApplicationManagementUtil.closeResultSet(stepInfoResultSet);
            IdentityApplicationManagementUtil.closeConnection(connection);
        }

    }

    final class ClaimsUrlValuesMap {
        private final String localClaimUrl;
        private final String remoteClaimUrl;
        private final String claimValue;

        public ClaimsUrlValuesMap(String localClaimUrl, String remoteClaimUrl, String claimValue) {
            this.localClaimUrl = localClaimUrl;
            this.remoteClaimUrl = remoteClaimUrl;
            this.claimValue = claimValue;
        }

        public String getLocalClaimUrl() {
            return localClaimUrl;
        }

        public String getClaimValue() {
            return claimValue;
        }

        public String getRemoteClaimUrl() {
            return remoteClaimUrl;
        }

    }
}