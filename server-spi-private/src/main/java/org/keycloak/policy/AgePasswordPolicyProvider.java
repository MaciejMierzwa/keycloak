package org.keycloak.policy;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.jboss.logging.Logger;

import java.util.stream.Stream;

public class AgePasswordPolicyProvider implements PasswordPolicyProvider {
    private static String ERROR_MESSAGE = "invalidPasswordGenericMessage";
    public static final Logger logger = Logger.getLogger(AgePasswordPolicyProvider.class);
    private KeycloakSession session;

    public AgePasswordPolicyProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PolicyError validate(String user, String password) {
        return null;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        PasswordPolicy policy = session.getContext().getRealm().getPasswordPolicy();
        int passwordAgePolicyValue = policy.getPolicyConfig(PasswordPolicy.PASSWORD_AGE);

        if (passwordAgePolicyValue != -1) {
            //current password check
            if (user.credentialManager().getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE)
                    .map(PasswordCredentialModel::createFromCredentialModel)
                    .anyMatch(passwordCredential -> {
                        PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class,
                                passwordCredential.getPasswordCredentialData().getAlgorithm());
                        return hash != null && hash.verify(password, passwordCredential);
                    })) {
                return new PolicyError(ERROR_MESSAGE, passwordAgePolicyValue);
            }

            final long passwordMaxAgeMillis = Time.currentTimeMillis() - Time.daysToMillis(passwordAgePolicyValue);
            if (passwordAgePolicyValue > 0) {
                if (user.credentialManager().getStoredCredentialsByTypeStream(PasswordCredentialModel.PASSWORD_HISTORY)
                        .filter(credentialModel -> credentialModel.getCreatedDate() > passwordMaxAgeMillis)
                        .map(PasswordCredentialModel::createFromCredentialModel)
                        .anyMatch(passwordCredential -> {
                            PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class,
                                    passwordCredential.getPasswordCredentialData().getAlgorithm());
                            return hash.verify(password, passwordCredential);
                        })) {
                    return new PolicyError(ERROR_MESSAGE, passwordAgePolicyValue);
                }
            }
        }
        return null;
    }

    private Stream<CredentialModel> getRecent(Stream<CredentialModel> passwordHistory, int limit) {
        return passwordHistory
                .sorted(CredentialModel.comparingByStartDateDesc())
                .limit(limit);
    }

    @Override
    public Object parseConfig(String value) {
        return parseInteger(value, AgePasswordPolicyProviderFactory.DEFAULT_AGE_DAYS);
    }

    @Override
    public void close() {
    }
}
