package net.unicon.idp.authn.provider.extra;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.env.Environment;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Generates a querystring parameter containing the authn_method parameter.
 *
 */
public class CasAuthnMethodParameterBuilderUsingConfMappings implements IParameterBuilder, ApplicationContextAware {
    private final Logger logger = LoggerFactory.getLogger(CasAuthnMethodParameterBuilderUsingConfMappings.class);
    private Map<String, String> ACR_mappings = new HashMap<>();

    @Override
    public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
        init(applicationContext.getEnvironment());
    }

    private void init(Environment environment) {
        var mappings = environment.getRequiredProperty("shibcas.authenticationContextClassMappings");
        for (var mapping : mappings.split(",")) {
            var fromTo = mapping.split("->", 2);
            if (fromTo.length != 2) throw new RuntimeException("invalid shibcas.authenticationContextClassMappings entry " + mapping);
            ACR_mappings.put(fromTo[0].trim(), fromTo[1].trim());
        }
        logger.debug("parsed shibcas.authenticationContextClassMappings: {}", ACR_mappings);
    }

    @Override
    public String getParameterString(final HttpServletRequest request, final String authenticationKey) {
        try {
            final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(authenticationKey, request);
            final AuthenticationContext authnContext = prc.ensureSubcontext(AuthenticationContext.class);
            if (authnContext == null) {
                logger.debug("No authentication context is available");
                return "";
            }
            final RequestedPrincipalContext principalCtx = authnContext.ensureSubcontext(RequestedPrincipalContext.class);
            if (principalCtx == null || principalCtx.getRequestedPrincipals().isEmpty()) {
                logger.debug("No authentication method parameter is found in the request attributes");
                return "";
            }
            for (var principal : principalCtx.getRequestedPrincipals()) {
                var casMethod = ACR_mappings.get(principal.getName());
                if (casMethod != null && !casMethod.isEmpty()) {
                    logger.debug("mapping RequestedAuthnContext {} to CAS authn_method={}", principal, casMethod);
                    return "&authn_method=" + casMethod;
                }
            }
            return "";
        } catch (final ExternalAuthenticationException e) {
            logger.error(e.getMessage(), e);
            return "";
        }
    }
    
}
