package net.unicon.idp.authn.provider.extra;

public class CasMultifactorRefedsToEsupOtpAuthnMethodParameterBuilder extends CasAuthnMethodParameterBuilder {
    @Override
    protected String getCasAuthenticationMethodFor(final String authnMethod) {
        return "mfa-esupotp" + "&acr_values=" + authnMethod;
    }
}
