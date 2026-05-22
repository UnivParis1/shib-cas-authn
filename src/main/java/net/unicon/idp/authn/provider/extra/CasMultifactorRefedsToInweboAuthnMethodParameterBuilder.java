package net.unicon.idp.authn.provider.extra;

public class CasMultifactorRefedsToInweboAuthnMethodParameterBuilder extends CasAuthnMethodParameterBuilder {
    @Override
    protected String getCasAuthenticationMethodFor(final String authnMethod) {
        if (isMultifactorRefedsProfile(authnMethod)) {
            return "mfa-inwebo";
        }
        return null;
    }
}
