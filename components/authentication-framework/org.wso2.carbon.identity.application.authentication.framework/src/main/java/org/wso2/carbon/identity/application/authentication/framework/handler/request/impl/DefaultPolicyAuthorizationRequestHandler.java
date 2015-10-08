package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PolicyAuthorizationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.CharacterEncoder;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtDBQueries;
import org.wso2.carbon.identity.application.mgt.dao.impl.ApplicationDAOImpl;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.ui.EntitlementPolicyConstants;
import org.wso2.carbon.identity.entitlement.ui.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.ui.dto.RowDTO;
import org.wso2.carbon.identity.entitlement.ui.util.PolicyCreatorUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
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
    private static final Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;
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
     * @param request
     * @param response
     * @throws org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            log.debug("In policy authorization flow");
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
                                ClaimsUrlValuesMap claimUrlValuesMap =getClaimsValuesByRequiredClaim(requiredClaim, claimValuesMap, claimMappingArray);
                                if (claimUrlValuesMap != null) {
                                    String claimValue = CharacterEncoder.getSafeText(claimUrlValuesMap.getClaimValue ());
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
                                int currentStep = context.getCurrentStep();
                                StepConfig stepConfig = sequenceConfig.getStepMap().get(currentStep);

                                context.setRequestAuthenticated(false);
                                stepConfig.setCompleted(true);
                            }
                            log.info("*********** is authorized " + decisionValue);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }


            }

        }
    }

    private Boolean evaluateDecision(String decisionValue) {
        DocumentBuilder db = null;
        Boolean decisionString = false;
        try {
            db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
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
                    if (nodeValue.equalsIgnoreCase("Deny")) {
                        return false;
                    } else {
                        return true;
                    }

                }
            }
            return false;

        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


        return decisionString;
    }

    private ClaimsUrlValuesMap getClaimsValuesByRequiredClaim(String requiredClaim,  Map<ClaimMapping, String> claimValuesMap, ClaimMapping[] claimMappingArray) {
        String remoteClaimName;
        ClaimsUrlValuesMap claimsUrlValuesMap  = null;
        for (int i = 0; i < claimMappingArray.length; i++) {
            String localClaimUrl = claimMappingArray[i].getLocalClaim().getClaimUri();
            if (localClaimUrl.equals(requiredClaim)) {
                remoteClaimName = claimMappingArray[i].getRemoteClaim().getClaimUri();

                for (Map.Entry<ClaimMapping, String> entry : claimValuesMap.entrySet()) {
                    ClaimMapping entryMap = entry.getKey();

                    if (entryMap.getRemoteClaim().getClaimUri().equals(remoteClaimName)) {
                        claimsUrlValuesMap = new ClaimsUrlValuesMap(localClaimUrl, remoteClaimName,entry.getValue());
                        return claimsUrlValuesMap;
                    }

                }

            }

        }
        return claimsUrlValuesMap;
    }


    private boolean GetPolicyAddingStatus(String spName, String tenantName, String idpName, String authenticatorName) {
        boolean isPolicyAdded = false;

        try {
            int tenantId = FrameworkServiceComponent.getRealmService().getTenantManager()
                    .getTenantId(tenantName);
            Connection connection = IdentityDatabaseUtil.getDBConnection();
            int authenticatorId = getAuthentictorID(connection, tenantId, idpName, authenticatorName);

            int spId = getApplicationIDByName(spName, tenantId, connection);
            isPolicyAdded = getPolicyAddedForSPAndAuthenticator(spId, authenticatorId, connection);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return isPolicyAdded;
    }

    /**
     * @param conn
     * @param tenantId
     * @param idpName
     * @param authenticatorName
     * @return
     * @throws java.sql.SQLException
     */
    private int getAuthentictorID(Connection conn, int tenantId, String idpName,
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
            IdentityApplicationManagementUtil.closeConnection(connection);
            log.error("Error in storing the application", e);
            throw new IdentityApplicationManagementException("Error while storing application", e);
        } finally {
            IdentityApplicationManagementUtil.closeResultSet(appidResult);
            IdentityApplicationManagementUtil.closeStatement(getAppIDPrepStmt);
        }

        return applicationId;
    }

    public boolean getPolicyAddedForSPAndAuthenticator(
            int applicationId, int authenticatorId, Connection connection) throws SQLException {
        PreparedStatement getPolicyInfoPrepStmt = null;
        ResultSet stepInfoResultSet = null;
        boolean isPolicyAdded = true;
        try {
       //     getPolicyInfoPrepStmt = connection
         //           .prepareStatement(ApplicationMgtDBQueries.LOAD_POLICY_ADDED_INFO_BY_APP_ID_AND_AUTHENTICATOR_ID);
           // getPolicyInfoPrepStmt.setInt(1, applicationId);
            //getPolicyInfoPrepStmt.setInt(2, authenticatorId);
            //stepInfoResultSet = getPolicyInfoPrepStmt.executeQuery();

//            if (stepInfoResultSet.next()) {
  //              isPolicyAdded = stepInfoResultSet.getInt(1) == 1 ? true : false;
    //            return isPolicyAdded;
      //      }
            return isPolicyAdded;
        } finally {
            IdentityApplicationManagementUtil.closeStatement(getPolicyInfoPrepStmt);
            IdentityApplicationManagementUtil.closeResultSet(stepInfoResultSet);
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

