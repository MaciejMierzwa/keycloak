package org.keycloak.testsuite.policy;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.common.util.Time;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractAuthTest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.function.Consumer;

import static org.keycloak.representations.idm.CredentialRepresentation.PASSWORD;
import static org.keycloak.testsuite.admin.ApiUtil.getCreatedId;


public class PasswordAgePolicyTest extends AbstractAuthTest {

    UserResource user;

    private void setPasswordAgePolicy(String passwordAge) {
        log.info(String.format("Setting %s", passwordAge));
        RealmRepresentation testRealmRepresentation = testRealmResource().toRepresentation();
        testRealmRepresentation.setPasswordPolicy(passwordAge);
        testRealmResource().update(testRealmRepresentation);
    }

    private void setPasswordAgePolicyValue(String value) {
        setPasswordAgePolicy(String.format("passwordAge(%s)", value));
    }

    private void setPasswordAgePolicyValue(int value) {
        setPasswordAgePolicyValue(String.valueOf(value));
    }

    public UserRepresentation createUserRepresentation(String username) {
        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setUsername(username);
        userRepresentation.setEmail(String.format("%s@email.test", userRepresentation.getUsername()));
        userRepresentation.setEmailVerified(true);
        return userRepresentation;
    }

    public UserResource createUser(UserRepresentation user) {
        String createdUserId;
        try (Response response = testRealmResource().users().create(user)) {
            createdUserId = getCreatedId(response);
        }
        return testRealmResource().users().get(createdUserId);
    }

    public void resetUserPassword(UserResource userResource, String newPassword) {
        CredentialRepresentation newCredential = new CredentialRepresentation();
        newCredential.setType(PASSWORD);
        newCredential.setValue(newPassword);
        newCredential.setTemporary(false);
        userResource.resetPassword(newCredential);
    }

    private void expectBadRequestException(Consumer<Void> f) {
        try {
            f.accept(null);
            throw new AssertionError("An expected BadRequestException was not thrown.");
        } catch (BadRequestException bre) {
            log.info("An expected BadRequestException was caught.");
        }
    }

    @Before
    public void before() {
        user = createUser(createUserRepresentation("test_user"));
    }

    @After
    public void after() {
        user.remove();
    }

    @Test
    public void testPasswordHistoryRetrySamePassword() {
        setPasswordAgePolicyValue(1);
        //set offset to 12h ago
        Time.setOffset(-12 * 60 * 60);
        resetUserPassword(user, "secret");
        //try to set again same password
        Time.setOffset(0);
        expectBadRequestException(f -> resetUserPassword(user, "secret"));
    }

    @Test
    public void testPasswordHistoryWithTwoPasswordsErrorThrown() {
        setPasswordAgePolicyValue(1);
        //set offset to 12h ago
        Time.setOffset(-12 * 60 * 60);
        resetUserPassword(user, "secret");
        Time.setOffset(-10 * 60 * 60);
        resetUserPassword(user, "secret1");

        //try to set again same password after 12h
        Time.setOffset(0);
        expectBadRequestException(f -> resetUserPassword(user, "secret"));
    }

    @Test
    public void testPasswordHistoryWithTwoPasswords() {
        setPasswordAgePolicyValue(1);
        //set offset to more than day ago
        Time.setOffset(-26 * 60 * 60);
        resetUserPassword(user, "secret");
        Time.setOffset(-10 * 60 * 60);
        resetUserPassword(user, "secret1");

        //try to set again same password after 25h
        Time.setOffset(0);
        resetUserPassword(user, "secret");
    }

    @Test
    public void testPasswordHistoryWithMultiplePasswordsErrorThrown() {
        setPasswordAgePolicyValue(30);
        //set offset to 29 days, 23:59:50h
        Time.setOffset(-30 * 24 * 60 * 60 + 10);
        resetUserPassword(user, "secret");
        Time.setOffset(-25 * 24 * 60 * 60);
        resetUserPassword(user, "secret1");
        Time.setOffset(-20 * 24 * 60 * 60);
        resetUserPassword(user, "secret2");
        Time.setOffset(-10 * 24 * 60 * 60);
        resetUserPassword(user, "secret3");

        //try to set again same password after 30 days, should throw error, 10 seconds too early
        Time.setOffset(0);
        expectBadRequestException(f -> resetUserPassword(user, "secret"));
    }

    @Test
    public void testPasswordHistoryWithMultiplePasswords() {
        setPasswordAgePolicyValue(30);
        //set offset to 30 days, +00:00:10 h ago
        Time.setOffset(-30 * 24 * 60 * 60 - 10);
        resetUserPassword(user, "secret");
        Time.setOffset(-25 * 24 * 60 * 60);
        resetUserPassword(user, "secret1");
        Time.setOffset(-20 * 24 * 60 * 60);
        resetUserPassword(user, "secret2");
        Time.setOffset(-10 * 24 * 60 * 60);
        resetUserPassword(user, "secret3");

        //try to set again same password after 30 days
        Time.setOffset(0);
        resetUserPassword(user, "secret");
    }
}
