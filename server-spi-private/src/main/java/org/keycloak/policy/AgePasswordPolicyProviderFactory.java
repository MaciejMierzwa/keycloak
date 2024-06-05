package org.keycloak.policy;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;

public class AgePasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {
    public static final Integer DEFAULT_AGE_DAYS = 30;

    @Override
    public String getId() {
        return PasswordPolicy.PASSWORD_AGE;
    }

    @Override
    public String getDisplayName() {
        return "Not Recently Used In Days";
    }

    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.INT_CONFIG_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_AGE_DAYS);
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return new AgePasswordPolicyProvider(session);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }
}
