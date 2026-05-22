package net.unicon.idp.authn.provider.extra;

public class CasMultifactorRefedsToYubikeyAuthnMethodParameterBuilder extends CasAuthnMethodParameterBuilder {
    @Override
    protected String getCasAuthenticationMethodFor(final String authnMethod) {
        if (isMultifactorRefedsProfile(authnMethod)) {
            return "mfa-yubikey";
        }
        return null;
    }
}
