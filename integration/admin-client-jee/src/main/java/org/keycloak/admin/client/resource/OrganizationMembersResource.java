/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.admin.client.resource;

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.keycloak.representations.idm.MemberRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;

public interface OrganizationMembersResource {

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    Response addMember(String userId);

    /**
     * Return all members in the organization.
     *
     * @return a list containing the organization members.
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<MemberRepresentation> getAll();

    /**
     * Return all organization members that match the specified filters.
     *
     * @param search a {@code String} representing either a member's username, e-mail, first name, or last name.
     * @param exact if {@code true}, the members will be searched using exact match for the {@code search} param - i.e.
     *              at least one of the username main attributes must match exactly the {@code search} param. If false,
     *              the method returns all members with at least one main attribute partially matching the {@code search} param.
     * @param first index of the first element (pagination offset).
     * @param max the maximum number of results.
     * @return a list containing the matched organization members.
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<MemberRepresentation> search(
            @QueryParam("search") String search,
            @QueryParam("exact") Boolean exact,
            @QueryParam("first") Integer first,
            @QueryParam("max") Integer max
    );

    @Path("{id}")
    OrganizationMemberResource member(@PathParam("id") String id);

    @POST
    @Path("invite-user")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    Response inviteUser(@FormParam("email") String email,
                        @FormParam("firstName") String firstName,
                        @FormParam("lastName") String lastName);

    @POST
    @Path("invite-existing-user")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    Response inviteExistingUser(@FormParam("id") String id);

    @Path("count")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    Long count();
}
