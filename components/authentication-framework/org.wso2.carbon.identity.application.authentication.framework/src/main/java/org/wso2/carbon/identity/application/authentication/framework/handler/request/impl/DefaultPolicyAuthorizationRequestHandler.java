package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.wso2.balana.utils.exception.PolicyBuilderException;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthorizationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PolicyAuthorizationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.CharacterEncoder;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.common.EntitlementPolicyConstants;
import org.wso2.carbon.identity.entitlement.common.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.common.dto.RowDTO;
import org.wso2.carbon.identity.entitlement.common.util.PolicyCreatorUtil;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.IOException;
import java.io.StringReader;
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
     * Executes the authorization flow
     *
     * @param request  request
     * @param response response
     * @param context context
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationContext context) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("In policy authorization flow...");
        }

        boolean isAuthorizationEnabled = false;
        String tenantResourceName = "";
        String idpResourceName = "";

        if (context != null) {
            int currentStep = context.getCurrentStep();
            SequenceConfig sequenceConfig = context.getSequenceConfig();
            if (sequenceConfig != null) {
                String spName = context.getServiceProviderName();
                String tenantName = context.getTenantDomain();

                if (sequenceConfig.getStepMap() != null) {
                    StepConfig idp = sequenceConfig.getStepMap().get(currentStep);
                    String authenticatedIdpName = idp.getAuthenticatedIdP();
                    int authenticatedOrder = idp.getOrder();
                    AuthenticatorConfig authenticatorConfig = idp.getAuthenticatorList().get(authenticatedOrder - 1);
                    IdentityProvider identityProvider = authenticatorConfig.getIdps().get(authenticatedIdpName);
                    FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = identityProvider.getFederatedAuthenticatorConfigs();
                    String authenticatorName = authenticatorConfig.getName();
                    for (int j = 0; j < federatedAuthenticatorConfigs.length; j++) {
                        if (authenticatorName == federatedAuthenticatorConfigs[j].getName()) {
                            isAuthorizationEnabled = federatedAuthenticatorConfigs[j].isAuthorizationEnabled();
                        }
                    }
                    tenantResourceName = spName + "@" + tenantName;
                    idpResourceName = authenticatedIdpName + "@" + tenantName;
                }
            }

            if (isAuthorizationEnabled) {
                List<RowDTO> rowDTOs = new ArrayList<RowDTO>();
                RowDTO rowDTOTenant = createDTOForClaim(tenantResourceName, "urn:oasis:names:tc:xacml:1.0:resource:tenant-id", "tenant");
                rowDTOs.add(rowDTOTenant);

                RowDTO rowDTOResource = createDTOForClaim(idpResourceName, "urn:oasis:names:tc:xacml:1.0:resource:idp-id", "idp");
                rowDTOs.add(rowDTOResource);

                Map<ClaimMapping, String> claimValuesMap = context.getSubject().getUserAttributes();
                ClaimMapping[] claimMappingArray = context.getExternalIdP().getClaimMappings();

                try {
                    ArrayList<ClaimsUrlValuesMap> claimUrlValuesArray = getClaimsValuesByRequiredClaim(claimValuesMap, claimMappingArray);
                    for (int i = 0; i < claimUrlValuesArray.size(); i++) {
                        ClaimsUrlValuesMap claimsUrlValuesMap = claimUrlValuesArray.get(i);
                        String claimValue = CharacterEncoder.getSafeText(claimsUrlValuesMap.getClaimValue());
                        String category = "access-subject";
                        RowDTO rowDTO = createDTOForClaim(claimValue, claimsUrlValuesMap.getLocalClaimUrl(), category);
                        rowDTOs.add(rowDTO);
                    }
                    RequestDTO requestDTO = new RequestDTO();
                    requestDTO.setRowDTOs(rowDTOs);
                    RequestElementDTO requestElementDTO = PolicyCreatorUtil.createRequestElementDTO(requestDTO);

                    String requestString = PolicyBuilder.getInstance().buildRequest(requestElementDTO);
                    String xacmlResponse = FrameworkServiceDataHolder.getInstance().getEntitlementService().getDecision(requestString);
                    Boolean isAuthorized = evaluateXacmlResponse(xacmlResponse);
                    if (!isAuthorized) {
                        context.setRequestAuthenticated(false);
                        context.getSequenceConfig().setAuthorized(false);
                        context.getSequenceConfig().setCompleted(true);
                    }
                } catch (PolicyBuilderException e) {
                    throw new FrameworkException("Policy Builder Exception occurred", e);

                } catch (EntitlementException e) {
                    throw new FrameworkException("Entitlement Exception occurred", e);
                }
            }
        }
    }

    private RowDTO createDTOForClaim(String resourceName, String attributeId, String categoryValue) {
        RowDTO rowDTOTenant = new RowDTO();
        rowDTOTenant.setAttributeValue(resourceName);
        rowDTOTenant.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
        rowDTOTenant.setAttributeId(attributeId);
        rowDTOTenant.setCategory("urn:oasis:names:tc:xacml:3.0:attribute-category:".concat(categoryValue));
        return rowDTOTenant;

    }

    private Boolean evaluateXacmlResponse(String xacmlResponse) throws FrameworkException {
        try {
            DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            InputSource is = new InputSource();
            is.setCharacterStream(new StringReader(xacmlResponse));
            Document doc = db.parse(is);

            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/Response/Result/Decision/text()");
            String decision = (String) expr.evaluate(doc, XPathConstants.STRING);
            if (decision.equalsIgnoreCase(EntitlementPolicyConstants.RULE_EFFECT_PERMIT)
                    || decision.equalsIgnoreCase(EntitlementPolicyConstants.RULE_EFFECT_NOT_APPLICABLE)) {
                return true;
            }

        } catch (ParserConfigurationException e) {
            throw new FrameworkException("Exception occurred while xacmlResponse processing", e);
        } catch (SAXException e) {
            throw new FrameworkException("Exception occurred while xacmlResponse processing", e);
        } catch (XPathExpressionException e) {
            throw new FrameworkException("Exception occurred while xacmlResponse processing", e);
        } catch (IOException e) {
            throw new FrameworkException("Exception occurred while xacmlResponse processing", e);
        }
        return false;
    }

    private ArrayList<ClaimsUrlValuesMap> getClaimsValuesByRequiredClaim(
            Map<ClaimMapping, String> claimValuesMap,
            ClaimMapping[] claimMappingArray) {
        String remoteClaimName;
        ArrayList<ClaimsUrlValuesMap> claimsMapArray = new ArrayList<ClaimsUrlValuesMap>();
        for (ClaimMapping aClaimMappingArray : claimMappingArray) {
            String localClaimUrl = aClaimMappingArray.getLocalClaim().getClaimUri();
            remoteClaimName = aClaimMappingArray.getRemoteClaim().getClaimUri();
            for (Map.Entry<ClaimMapping, String> entry : claimValuesMap.entrySet()) {
                ClaimMapping entryMap = entry.getKey();
                if (entryMap.getRemoteClaim().getClaimUri().equals(remoteClaimName)) {
                    ClaimsUrlValuesMap claimsUrlValuesMap = new ClaimsUrlValuesMap(localClaimUrl, remoteClaimName, entry.getValue());
                    claimsMapArray.add(claimsUrlValuesMap);
                }
            }
        }
        return claimsMapArray;
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