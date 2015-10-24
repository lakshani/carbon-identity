package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.balana.utils.exception.PolicyBuilderException;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PolicyAuthorizationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.util.CharacterEncoder;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtDBQueries;
import org.wso2.carbon.identity.application.mgt.dao.impl.ApplicationDAOImpl;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.ui.EntitlementPolicyConstants;
import org.wso2.carbon.identity.entitlement.ui.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.ui.dto.RowDTO;
import org.wso2.carbon.identity.entitlement.ui.util.PolicyCreatorUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DefaultPolicyAuthorizationRequestHandler implements PolicyAuthorizationRequestHandler{
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

        if(context != null) {
            SequenceConfig sequenceConfig = context.getSequenceConfig();
            if (sequenceConfig != null) {
                String spName = context.getServiceProviderName();
                String tenantName = context.getTenantDomain();
                if (sequenceConfig.getStepMap() != null) {
                    StepConfig idp = sequenceConfig.getStepMap().get(1);
                    String idpName = idp.getAuthenticatedIdP();
                    String authenticatorName = "";
                    if(idp.getAuthenticatedAutenticator() != null) {
                        authenticatorName = idp.getAuthenticatedAutenticator().getName();
                    }
                    isPolicyAdded = GetPolicyAddingStatus(spName, tenantName, idpName, authenticatorName);
                    tenantResourceName = spName + "@" + tenantName;
                    idpResourceName = idpName + "@" + tenantName;

                }
            }


            if(isPolicyAdded) {
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

                Map<String, String> unfilteredClaimValues = (Map<String, String>) context
                        .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);

                if (sequenceConfig != null) {
                    try {
                        ApplicationConfig applicationConfig = sequenceConfig.getApplicationConfig();
                        if (applicationConfig != null) {
                            Map<String, String> requiredClaimMap = applicationConfig.getRequestedClaimMappings();
                            for (Map.Entry<String, String> entry : requiredClaimMap.entrySet()) {
                                String requiredClaim = entry.getValue();
                                if (unfilteredClaimValues != null) {
                                    for (Map.Entry<String, String> unifiedEntry : unfilteredClaimValues.entrySet()) {
                                        if (unifiedEntry.getKey().equals(requiredClaim)) {
                                            String claimValue = CharacterEncoder.getSafeText(unifiedEntry.getValue());
                                            RowDTO rowDTO = new RowDTO();
                                            rowDTO.setAttributeValue(claimValue);
                                            rowDTO.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
                                            rowDTO.setAttributeId(requiredClaim);
                                            rowDTO.setCategory("urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
                                            rowDTOs.add(rowDTO);
                                        }
                                    }
                                }
                            }

                            RequestDTO requestDTO = new RequestDTO();
                            requestDTO.setRowDTOs(rowDTOs);

                            RequestElementDTO requestElementDTO = PolicyCreatorUtil.createRequestElementDTO(requestDTO);


                            String requestString = PolicyBuilder.getInstance().buildRequest(requestElementDTO);
                            String authorizationString = FrameworkServiceDataHolder.getInstance().getEntitlementService().getDecision(requestString);
                            log.info("*********** is authorized ");
                        }
                    } catch (Exception e) {
                            e.printStackTrace();
                    }

                }


            }

        }
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
        boolean isPolicyAdded = false;

        try {
            getPolicyInfoPrepStmt = connection
                    .prepareStatement(ApplicationMgtDBQueries.LOAD_POLICY_ADDED_INFO_BY_APP_ID_AND_AUTHENTICATOR_ID);
            // STEP_ORDER, AUTHENTICATOR_ID, IS_SUBJECT_STEP, IS_ATTRIBUTE_STEP
            getPolicyInfoPrepStmt.setInt(1, applicationId);
            getPolicyInfoPrepStmt.setInt(2, authenticatorId);
            stepInfoResultSet = getPolicyInfoPrepStmt.executeQuery();

            if (stepInfoResultSet.next()) {
                isPolicyAdded = stepInfoResultSet.getInt(1) == 1 ? true:false;
                return isPolicyAdded;
            }
            return isPolicyAdded;
        } finally {
            IdentityApplicationManagementUtil.closeStatement(getPolicyInfoPrepStmt);
            IdentityApplicationManagementUtil.closeResultSet(stepInfoResultSet);
        }

    }
}


