package net.unicon.idp.authn.provider.extra;

public class CasMultifactorRefedsToEsupOtpAuthnMethodParameterBuilder extends CasAuthnMethodParameterBuilder {
    @Override
    protected String getCasAuthenticationMethodFor(final String authnMethod) {
        if (isMultifactorRefedsProfile(authnMethod)) {
            return "mfa-esupotp";
        }
        return null;
    }
}
