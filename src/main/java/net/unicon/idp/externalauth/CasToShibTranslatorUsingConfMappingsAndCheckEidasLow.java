package net.unicon.idp.externalauth;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.principal.PrincipalEvalPredicate;
import net.shibboleth.idp.authn.principal.PrincipalEvalPredicateFactory;
import net.shibboleth.idp.authn.principal.PrincipalSupportingComponent;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.client.validation.Assertion;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;

import javax.annotation.Nonnull;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class CasToShibTranslatorUsingConfMappingsAndCheckEidasLow implements CasToShibTranslator, EnvironmentAware {
    private final Logger logger = LoggerFactory.getLogger(CasToShibTranslatorUsingConfMappingsAndCheckEidasLow.class);

    private Multimap<String, String> ACR_mappings = HashMultimap.create();
    
    /**
     * The default authentication context class to include in the response
     * if none is specified via the service.
     */
    private String defaultAuthnContextClass;

    @Override
    public void setEnvironment(final Environment environment) {
        init(environment);
    }

    /**
     * Check the idp's idp.properties, authn.properties files for the intialization
     * of the default AuthnContextClass when MFA can't be done
     *
     * @return String defaultAuthnContextClass
     */
    private void init(Environment environment) {
        defaultAuthnContextClass = StringUtils.defaultIfBlank(environment.getProperty("shibcas.defaultAuthnContextClass"), AuthnContext.PPT_AUTHN_CTX);
        logger.debug("shibcas.defaultAuthnContextClass: {}", defaultAuthnContextClass);

        var mappings = environment.getRequiredProperty("shibcas.authenticationContextClassMappings");
        for (var mapping : mappings.split(",")) {
            var fromTo = mapping.split("->", 2);
            if (fromTo.length != 2) throw new RuntimeException("invalid shibcas.authenticationContextClassMappings entry " + mapping);
            ACR_mappings.put(fromTo[1].trim(), fromTo[0].trim());
        }
        logger.debug("parsed reversed shibcas.authenticationContextClassMappings: {}", ACR_mappings);        
    }

    @Override
    public void doTranslation(final HttpServletRequest request, final HttpServletResponse response, final Assertion assertion, final String authenticationKey) throws Exception {

        final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(authenticationKey, request);
        final AuthenticationContext authnContext = prc.ensureSubcontext(AuthenticationContext.class);
        if (authnContext == null) {
            logger.error("No authentication context is available");
            return;
        }
        var requestedContext = authnContext.ensureSubcontext(RequestedPrincipalContext.class);
        var casResponseACR = assertion.getPrincipal().getAttributes().get("authnContextClass");
        logger.debug("casResponseACR {}", casResponseACR);

        var responseACR = computeResponseACR(
            requestedContext != null ? requestedContext.getRequestedPrincipals() : null, 
            casResponseACR != null ? casResponseACR.toString() : ""
        );

        if (responseACR != null && responseACR.startsWith("http://eidas.europa.eu/LoA/low") && !isEidasLow(assertion.getPrincipal().getAttributes())) {
            logger.info("User is not http://eidas.europa.eu/LoA/low");
            responseACR = null;
        }

        if (responseACR != null) {
            overrideAuthnContextClass(responseACR, request, authenticationKey);
        } else {
            request.setAttribute(ExternalAuthentication.AUTHENTICATION_EVENT_KEY, AuthnEventIds.REQUEST_UNSUPPORTED);
        }
    }

    private boolean isEidasLow(Map<String, Object> attributes) {
        // TODO
                
        var affs = attributes.get("eduPersonAffiliation");
        logger.debug("User eduPersonAffiliation: {}", affs);
        if (affs instanceof Collection affs_) {
            return affs_.contains("member") && affs_.contains("employee");
        } else {
            return false;
        }
    }

    private String computeResponseACR(List<Principal> requestedPrincipals, String casResponseACR) {
        if (requestedPrincipals == null || requestedPrincipals.isEmpty()) {
            if (casResponseACR != null) {                
                logger.debug("ignoring casResponseACR ({}) since no requestedAuthnContext", casResponseACR);            
            } else {
                logger.debug("no requestedContext and no casResponseACR");                
            }
            // responding a generic non-MFA ACR
            return defaultAuthnContextClass;
        } else {
            var responseACR = computeResponseACR_(requestedPrincipals, casResponseACR);
            if (responseACR != null) return responseACR;

            if (!casResponseACR.equals("")) {               
                // fallback in case of over achieved ACR
                responseACR = computeResponseACR_(requestedPrincipals, "");
            }
            if (responseACR != null) return responseACR;

            logger.warn("ignoring casResponseACR ({}) since reverse mapping does not match requestedAuthnContext {}", casResponseACR, requestedPrincipals);
            return null;
        }        
    }

    private String computeResponseACR_(List<Principal> requestedPrincipals, String casResponseACR) {
        var possible_ACRs = ACR_mappings.get(casResponseACR);
        for (var principal : requestedPrincipals) {
            if (possible_ACRs.contains(principal.getName())) {
                logger.info("Choosing response ACR {} since this reverse mapping of CAS ACR {} matches requestedAuthnContext {}", principal.getName(), casResponseACR, requestedPrincipals);
                return principal.getName();
            }
        }
        return null;
    }
    
    private void overrideAuthnContextClass(final String clazz, final HttpServletRequest request, final String authenticationKey) throws Exception {
        final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(authenticationKey, request);
        final AuthenticationContext authnContext = prc.ensureSubcontext(AuthenticationContext.class);
        if (authnContext == null) {
            throw new IllegalArgumentException("No authentication method parameter is found in the request attributes");
        }
        final RequestedPrincipalContext principalCtx = authnContext.ensureSubcontext(RequestedPrincipalContext.class);
        if (principalCtx != null) {
            final List<Principal> principals = new ArrayList<>();
            final Principal principal = new AuthnContextClassRefPrincipal(clazz);
            principals.add(principal);
            principalCtx.setRequestedPrincipals(principals);
            principalCtx.setOperator("exact");
            principalCtx.setMatchingPrincipal(principal);

            principalCtx.getPrincipalEvalPredicateFactoryRegistry().register(AuthnContextClassRefPrincipal.class, "exact", new PrincipalEvalPredicateFactory() {
                @Nonnull
                @Override
                public PrincipalEvalPredicate getPredicate(@Nonnull final Principal candidate) {
                    return new PrincipalEvalPredicate() {

                        @Override
                        public boolean test(PrincipalSupportingComponent principalSupportingComponent) {
                            return principalSupportingComponent != null && principalSupportingComponent.getSupportedPrincipals(principal.getClass()).contains(principal);
                        }

                        @Override
                        public Principal getMatchingPrincipal() {
                            return principal;
                        }
                    };
                }
            });

            logger.debug("The final requested authn context class ref principals are {}", principals);
        } else {
            logger.error("No requested principal context class is available");
        }
    }
}
