package net.unicon.idp.authn.provider.extra;

public class CasMultifactorRefedsToRadiusAuthnMethodParameterBuilder extends CasAuthnMethodParameterBuilder {
    @Override
    protected String getCasAuthenticationMethodFor(final String authnMethod) {
        if (isMultifactorRefedsProfile(authnMethod)) {
            return "mfa-radius";
        }
        return null;
    }
}
