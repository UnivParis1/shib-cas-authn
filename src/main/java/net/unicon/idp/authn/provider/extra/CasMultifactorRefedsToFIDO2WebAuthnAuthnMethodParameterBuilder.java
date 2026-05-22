package net.unicon.idp.authn.provider.extra;

public class CasMultifactorRefedsToFIDO2WebAuthnAuthnMethodParameterBuilder extends CasAuthnMethodParameterBuilder {
    @Override
    protected String getCasAuthenticationMethodFor(final String authnMethod) {
        if (isMultifactorRefedsProfile(authnMethod)) {
            return "mfa-webauthn";
        }
        return null;
    }
}
