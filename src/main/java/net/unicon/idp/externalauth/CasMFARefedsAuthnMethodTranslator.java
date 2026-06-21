package net.unicon.idp.externalauth;

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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CasMFARefedsAuthnMethodTranslator implements CasToShibTranslator, EnvironmentAware {
    private final Logger logger = LoggerFactory.getLogger(CasMFARefedsAuthnMethodTranslator.class);

    private static final String REFEDS = "https://refeds.org/profile/mfa";

    private static final Set<String> ALLOWED_MFA_AUTHN_CLASSES = Set.of(
            REFEDS,
            "mfa-simple", "mfa-webauthn", "mfa-duo",
            "mfa-radius", "mfa-gauth", "mfa-yubikey",
            "mfa-inwebo", "mfa-esupotp"
        );

    private Environment environment;

    /**
     * The default authentication context class to include in the response
     * if none is specified via the service.
     */
    private String defaultAuthnContextClass;

    @Override
    public void setEnvironment(final Environment environment) {
        this.environment = environment;
        // init properties when the environment is intiated or set
        this.defaultAuthnContextClass = initDefaultAuthnContextClass();

    }

    /**
     * Check the idp's idp.properties, authn.properties files for the intialization
     * of the default AuthnContextClass when MFA can't be done
     *
     * @return String defaultAuthnContextClass
     */
    private String initDefaultAuthnContextClass() {
        String initiatedDefaultAuthnContextClass = StringUtils.defaultIfBlank(environment.getProperty("shibcas.defaultAuthnContextClass"), AuthnContext.PPT_AUTHN_CTX);
        logger.debug("shibcas.defaultAuthnContextClass: {}", initiatedDefaultAuthnContextClass);
        return initiatedDefaultAuthnContextClass;
    }

    @Override
    public void doTranslation(final HttpServletRequest request, final HttpServletResponse response, final Assertion assertion, final String authenticationKey) throws Exception {

        final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(authenticationKey, request);
        final AuthenticationContext authnContext = prc.ensureSubcontext(AuthenticationContext.class);
        if (authnContext == null) {
            logger.debug("No authentication context is available");
            return;
        }
        final RequestedPrincipalContext principalCtx = authnContext.ensureSubcontext(RequestedPrincipalContext.class);
        if (principalCtx == null) {
            logger.debug("No requested principal context is available in the authentication context; Overriding class to {}", defaultAuthnContextClass);
            overrideAuthnContextClass(defaultAuthnContextClass, request, authenticationKey);
            return;
        }

        final Principal principal = new AuthnContextClassRefPrincipal(REFEDS);
        final Principal attribute = principalCtx.getRequestedPrincipals().stream().filter(p -> p.equals(principal)).findFirst().orElse(null);
        final String authnMethod = attribute == null ? null : attribute.getName();
        logger.debug("Requested authn method provided by IdP is {}", authnMethod);
        if (!assertion.getPrincipal().getAttributes().containsKey("authnContextClass")) {
            logger.debug("No authentication context class is provided by CAS; Overriding context class to {}", defaultAuthnContextClass);
            overrideAuthnContextClass(defaultAuthnContextClass, request, authenticationKey);
            return;
        }

        final Object clazz = assertion.getPrincipal().getAttributes().get("authnContextClass");

        if (ALLOWED_MFA_AUTHN_CLASSES.contains(clazz.toString())) {
            overrideAuthnContextClass(REFEDS, request, authenticationKey);
            logger.info("Validation payload successfully asserts the authentication context class for {}; Context class is set to {}", clazz, REFEDS);
        } else {
            logger.warn("Authentication context class provided by CAS is not allowed. The requested authentication method to be used shall be {} and is left unmodified", authnMethod);
            overrideAuthnContextClass(authnMethod, request, authenticationKey);
        }
    }

    private void overrideAuthnContextClass(final String clazz, final HttpServletRequest request, final String authenticationKey) throws Exception {
        final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(authenticationKey, request);
        final AuthenticationContext authnContext = prc.ensureSubcontext(AuthenticationContext.class);
        if (authnContext == null) {
            throw new IllegalArgumentException("No authentication method parameter is found in the request attributes");
        }
        final RequestedPrincipalContext principalCtx = authnContext.ensureSubcontext(RequestedPrincipalContext.class);
        logger.info("Overriding the principal authn context class ref to {}", clazz);
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

            logger.info("The final requested authn context class ref principals are {}", principals);
        } else {
            logger.error("No requested principal context class is available");
        }
    }
}
