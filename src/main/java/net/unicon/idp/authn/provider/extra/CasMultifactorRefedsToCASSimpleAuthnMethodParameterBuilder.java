package net.unicon.idp.authn.provider.extra;

public class CasMultifactorRefedsToCASSimpleAuthnMethodParameterBuilder extends CasAuthnMethodParameterBuilder {
    @Override
    protected String getCasAuthenticationMethodFor(final String authnMethod) {
        if (isMultifactorRefedsProfile(authnMethod)) {
            return "mfa-simple";
        }
        return null;
    }
}
