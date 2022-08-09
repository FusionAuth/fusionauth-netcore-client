/*
 * Copyright (c) 2018-2022, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using io.fusionauth.domain;
using io.fusionauth.domain.api;
using io.fusionauth.domain.api.email;
using io.fusionauth.domain.api.identityProvider;
using io.fusionauth.domain.api.jwt;
using io.fusionauth.domain.api.passwordless;
using io.fusionauth.domain.api.report;
using io.fusionauth.domain.api.twoFactor;
using io.fusionauth.domain.api.user;
using io.fusionauth.domain.oauth2;
using io.fusionauth.domain.provider;
using io.fusionauth.domain.reactor;

namespace io.fusionauth {
  public class FusionAuthClient : IFusionAuthAsyncClient {
    public readonly string apiKey;

    public readonly string host;

    public readonly string tenantId;

    public readonly IRESTClientBuilder clientBuilder;

    public FusionAuthClient(string apiKey, string host, string tenantId = null) {
      this.apiKey = apiKey;
      this.host = host;
      this.tenantId = tenantId;

      clientBuilder = new DefaultRESTClientBuilder();
    }

    /**
     * Return a new instance of FusionAuthClient using the provided tenantId.
     * @param tenantId the tenantId to use for this client.
     */
    // ReSharper disable once ParameterHidesMember
    public FusionAuthClient withTenantId(string tenantId) {
      return tenantId == null ? this : new FusionAuthClient(apiKey, host, tenantId);
    }

    /**
     * Return a new instance of FusionAuthClient using the provided tenantId.
     * @param tenantId the tenantId to use for this client.
     */
    // ReSharper disable once ParameterHidesMember
    public FusionAuthClient withTenantId(Guid? tenantId) {
      return tenantId == null ? this : new FusionAuthClient(apiKey, host, tenantId.ToString());
    }

    public IRESTClient buildClient() {
      return buildAnonymousClient().withAuthorization(apiKey);
    }

    public IRESTClient buildAnonymousClient() {
      var client = clientBuilder.build(host);

      if (tenantId != null) {
        client.withHeader("X-FusionAuth-TenantId", tenantId);
      }

      return client;
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ActionResponse>> ActionUserAsync(ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> ActivateReactorAsync(ReactorRequest request) {
      return buildClient()
          .withUri("/api/reactor")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FamilyResponse>> AddUserToFamilyAsync(Guid? familyId, FamilyRequest request) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<FamilyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ActionResponse>> CancelActionAsync(Guid? actionId, ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<ActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ChangePasswordResponse>> ChangePasswordAsync(string changePasswordId, ChangePasswordRequest request) {
      return buildAnonymousClient()
          .withUri("/api/user/change-password")
          .withUriSegment(changePasswordId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ChangePasswordResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> ChangePasswordByIdentityAsync(ChangePasswordRequest request) {
      return buildClient()
          .withUri("/api/user/change-password")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> CheckChangePasswordUsingIdAsync(string changePasswordId) {
      return buildAnonymousClient()
          .withUri("/api/user/change-password")
          .withUriSegment(changePasswordId)
          .withMethod("Get")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> CheckChangePasswordUsingJWTAsync(string encodedJWT) {
      return buildAnonymousClient()
          .withUri("/api/user/change-password")
          .withAuthorization("Bearer " + encodedJWT)
          .withMethod("Get")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> CheckChangePasswordUsingLoginIdAsync(string loginId) {
      return buildClient()
          .withUri("/api/user/change-password")
          .withParameter("username", loginId)
          .withMethod("Get")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> CommentOnUserAsync(UserCommentRequest request) {
      return buildClient()
          .withUri("/api/user/comment")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<APIKeyResponse>> CreateAPIKeyAsync(Guid? keyId, APIKeyRequest request) {
      return buildClient()
          .withUri("/api/api-key")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<APIKeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> CreateApplicationAsync(Guid? applicationId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> CreateApplicationRoleAsync(Guid? applicationId, Guid? roleId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<AuditLogResponse>> CreateAuditLogAsync(AuditLogRequest request) {
      return buildClient()
          .withUri("/api/system/audit-log")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<AuditLogResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConnectorResponse>> CreateConnectorAsync(Guid? connectorId, ConnectorRequest request) {
      return buildClient()
          .withUri("/api/connector")
          .withUriSegment(connectorId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ConnectorResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConsentResponse>> CreateConsentAsync(Guid? consentId, ConsentRequest request) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EmailTemplateResponse>> CreateEmailTemplateAsync(Guid? emailTemplateId, EmailTemplateRequest request) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EmailTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityResponse>> CreateEntityAsync(Guid? entityId, EntityRequest request) {
      return buildClient()
          .withUri("/api/entity")
          .withUriSegment(entityId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EntityResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityTypeResponse>> CreateEntityTypeAsync(Guid? entityTypeId, EntityTypeRequest request) {
      return buildClient()
          .withUri("/api/entity/type")
          .withUriSegment(entityTypeId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EntityTypeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityTypeResponse>> CreateEntityTypePermissionAsync(Guid? entityTypeId, Guid? permissionId, EntityTypeRequest request) {
      return buildClient()
          .withUri("/api/entity/type")
          .withUriSegment(entityTypeId)
          .withUriSegment("permission")
          .withUriSegment(permissionId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EntityTypeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FamilyResponse>> CreateFamilyAsync(Guid? familyId, FamilyRequest request) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<FamilyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FormResponse>> CreateFormAsync(Guid? formId, FormRequest request) {
      return buildClient()
          .withUri("/api/form")
          .withUriSegment(formId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<FormResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FormFieldResponse>> CreateFormFieldAsync(Guid? fieldId, FormFieldRequest request) {
      return buildClient()
          .withUri("/api/form/field")
          .withUriSegment(fieldId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<FormFieldResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<GroupResponse>> CreateGroupAsync(Guid? groupId, GroupRequest request) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<GroupResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MemberResponse>> CreateGroupMembersAsync(MemberRequest request) {
      return buildClient()
          .withUri("/api/group/member")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<MemberResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IPAccessControlListResponse>> CreateIPAccessControlListAsync(Guid? accessControlListId, IPAccessControlListRequest request) {
      return buildClient()
          .withUri("/api/ip-acl")
          .withUriSegment(accessControlListId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<IPAccessControlListResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderResponse>> CreateIdentityProviderAsync(Guid? identityProviderId, IdentityProviderRequest request) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<IdentityProviderResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LambdaResponse>> CreateLambdaAsync(Guid? lambdaId, LambdaRequest request) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LambdaResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessageTemplateResponse>> CreateMessageTemplateAsync(Guid? messageTemplateId, MessageTemplateRequest request) {
      return buildClient()
          .withUri("/api/message/template")
          .withUriSegment(messageTemplateId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<MessageTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessengerResponse>> CreateMessengerAsync(Guid? messengerId, MessengerRequest request) {
      return buildClient()
          .withUri("/api/messenger")
          .withUriSegment(messengerId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<MessengerResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TenantResponse>> CreateTenantAsync(Guid? tenantId, TenantRequest request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<TenantResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ThemeResponse>> CreateThemeAsync(Guid? themeId, ThemeRequest request) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ThemeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> CreateUserAsync(Guid? userId, UserRequest request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionResponse>> CreateUserActionAsync(Guid? userActionId, UserActionRequest request) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<UserActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionReasonResponse>> CreateUserActionReasonAsync(Guid? userActionReasonId, UserActionReasonRequest request) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<UserActionReasonResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserConsentResponse>> CreateUserConsentAsync(Guid? userConsentId, UserConsentRequest request) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<UserConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderLinkResponse>> CreateUserLinkAsync(IdentityProviderLinkRequest request) {
      return buildClient()
          .withUri("/api/identity-provider/link")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<IdentityProviderLinkResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<WebhookResponse>> CreateWebhookAsync(Guid? webhookId, WebhookRequest request) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<WebhookResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeactivateApplicationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeactivateReactorAsync() {
      return buildClient()
          .withUri("/api/reactor")
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeactivateUserAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeactivateUserActionAsync(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to DeactivateUsersByIdsAsync, use that method instead.")]
    public Task<ClientResponse<UserDeleteResponse>> DeactivateUsersAsync(List<string> userIds) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withParameter("userId", userIds)
          .withParameter("dryRun", false)
          .withParameter("hardDelete", false)
          .withMethod("Delete")
          .goAsync<UserDeleteResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserDeleteResponse>> DeactivateUsersByIdsAsync(List<string> userIds) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withParameter("userId", userIds)
          .withParameter("dryRun", false)
          .withParameter("hardDelete", false)
          .withMethod("Delete")
          .goAsync<UserDeleteResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteAPIKeyAsync(Guid? keyId) {
      return buildClient()
          .withUri("/api/api-key")
          .withUriSegment(keyId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteApplicationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteApplicationRoleAsync(Guid? applicationId, Guid? roleId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteConnectorAsync(Guid? connectorId) {
      return buildClient()
          .withUri("/api/connector")
          .withUriSegment(connectorId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteConsentAsync(Guid? consentId) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteEmailTemplateAsync(Guid? emailTemplateId) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteEntityAsync(Guid? entityId) {
      return buildClient()
          .withUri("/api/entity")
          .withUriSegment(entityId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteEntityGrantAsync(Guid? entityId, Guid? recipientEntityId, Guid? userId) {
      return buildClient()
          .withUri("/api/entity")
          .withUriSegment(entityId)
          .withUriSegment("grant")
          .withParameter("recipientEntityId", recipientEntityId)
          .withParameter("userId", userId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteEntityTypeAsync(Guid? entityTypeId) {
      return buildClient()
          .withUri("/api/entity/type")
          .withUriSegment(entityTypeId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteEntityTypePermissionAsync(Guid? entityTypeId, Guid? permissionId) {
      return buildClient()
          .withUri("/api/entity/type")
          .withUriSegment(entityTypeId)
          .withUriSegment("permission")
          .withUriSegment(permissionId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteFormAsync(Guid? formId) {
      return buildClient()
          .withUri("/api/form")
          .withUriSegment(formId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteFormFieldAsync(Guid? fieldId) {
      return buildClient()
          .withUri("/api/form/field")
          .withUriSegment(fieldId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteGroupAsync(Guid? groupId) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteGroupMembersAsync(MemberDeleteRequest request) {
      return buildClient()
          .withUri("/api/group/member")
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteIPAccessControlListAsync(Guid? ipAccessControlListId) {
      return buildClient()
          .withUri("/api/ip-acl")
          .withUriSegment(ipAccessControlListId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteIdentityProviderAsync(Guid? identityProviderId) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteKeyAsync(Guid? keyId) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteLambdaAsync(Guid? lambdaId) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteMessageTemplateAsync(Guid? messageTemplateId) {
      return buildClient()
          .withUri("/api/message/template")
          .withUriSegment(messageTemplateId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteMessengerAsync(Guid? messengerId) {
      return buildClient()
          .withUri("/api/messenger")
          .withUriSegment(messengerId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteRegistrationAsync(Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteRegistrationWithRequestAsync(Guid? userId, Guid? applicationId, RegistrationDeleteRequest request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteTenantAsync(Guid? tenantId) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteTenantAsyncAsync(Guid? tenantId) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withParameter("async", true)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteTenantWithRequestAsync(Guid? tenantId, TenantDeleteRequest request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteThemeAsync(Guid? themeId) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteUserAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteUserActionAsync(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteUserActionReasonAsync(Guid? userActionReasonId) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderLinkResponse>> DeleteUserLinkAsync(Guid? identityProviderId, string identityProviderUserId, Guid? userId) {
      return buildClient()
          .withUri("/api/identity-provider/link")
          .withParameter("identityProviderId", identityProviderId)
          .withParameter("identityProviderUserId", identityProviderUserId)
          .withParameter("userId", userId)
          .withMethod("Delete")
          .goAsync<IdentityProviderLinkResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteUserWithRequestAsync(Guid? userId, UserDeleteSingleRequest request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to DeleteUsersByQueryAsync, use that method instead.")]
    public Task<ClientResponse<UserDeleteResponse>> DeleteUsersAsync(UserDeleteRequest request) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<UserDeleteResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserDeleteResponse>> DeleteUsersByQueryAsync(UserDeleteRequest request) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<UserDeleteResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DeleteWebhookAsync(Guid? webhookId) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DisableTwoFactorAsync(Guid? userId, string methodId, string code) {
      return buildClient()
          .withUri("/api/user/two-factor")
          .withUriSegment(userId)
          .withParameter("methodId", methodId)
          .withParameter("code", code)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> DisableTwoFactorWithRequestAsync(Guid? userId, TwoFactorDisableRequest request) {
      return buildClient()
          .withUri("/api/user/two-factor")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TwoFactorResponse>> EnableTwoFactorAsync(Guid? userId, TwoFactorRequest request) {
      return buildClient()
          .withUri("/api/user/two-factor")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<TwoFactorResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<AccessToken>> ExchangeOAuthCodeForAccessTokenAsync(string code, string client_id, string client_secret, string redirect_uri) {
      var body = new Dictionary<string, string> {
          { "code", code },
          { "client_id", client_id },
          { "client_secret", client_secret },
          { "grant_type", "authorization_code" },
          { "redirect_uri", redirect_uri },
      };
      return buildAnonymousClient()
          .withUri("/oauth2/token")
          .withFormData(new FormUrlEncodedContent(body))
          .withMethod("Post")
          .goAsync<AccessToken>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<AccessToken>> ExchangeOAuthCodeForAccessTokenUsingPKCEAsync(string code, string client_id, string client_secret, string redirect_uri, string code_verifier) {
      var body = new Dictionary<string, string> {
          { "code", code },
          { "client_id", client_id },
          { "client_secret", client_secret },
          { "grant_type", "authorization_code" },
          { "redirect_uri", redirect_uri },
          { "code_verifier", code_verifier },
      };
      return buildAnonymousClient()
          .withUri("/oauth2/token")
          .withFormData(new FormUrlEncodedContent(body))
          .withMethod("Post")
          .goAsync<AccessToken>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<AccessToken>> ExchangeRefreshTokenForAccessTokenAsync(string refresh_token, string client_id, string client_secret, string scope, string user_code) {
      var body = new Dictionary<string, string> {
          { "refresh_token", refresh_token },
          { "client_id", client_id },
          { "client_secret", client_secret },
          { "grant_type", "refresh_token" },
          { "scope", scope },
          { "user_code", user_code },
      };
      return buildAnonymousClient()
          .withUri("/oauth2/token")
          .withFormData(new FormUrlEncodedContent(body))
          .withMethod("Post")
          .goAsync<AccessToken>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<JWTRefreshResponse>> ExchangeRefreshTokenForJWTAsync(RefreshRequest request) {
      return buildAnonymousClient()
          .withUri("/api/jwt/refresh")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<JWTRefreshResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<AccessToken>> ExchangeUserCredentialsForAccessTokenAsync(string username, string password, string client_id, string client_secret, string scope, string user_code) {
      var body = new Dictionary<string, string> {
          { "username", username },
          { "password", password },
          { "client_id", client_id },
          { "client_secret", client_secret },
          { "grant_type", "password" },
          { "scope", scope },
          { "user_code", user_code },
      };
      return buildAnonymousClient()
          .withUri("/oauth2/token")
          .withFormData(new FormUrlEncodedContent(body))
          .withMethod("Post")
          .goAsync<AccessToken>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ForgotPasswordResponse>> ForgotPasswordAsync(ForgotPasswordRequest request) {
      return buildClient()
          .withUri("/api/user/forgot-password")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ForgotPasswordResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<VerifyEmailResponse>> GenerateEmailVerificationIdAsync(string email) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withParameter("email", email)
          .withParameter("sendVerifyEmail", false)
          .withMethod("Put")
          .goAsync<VerifyEmailResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<KeyResponse>> GenerateKeyAsync(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key/generate")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<KeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<VerifyRegistrationResponse>> GenerateRegistrationVerificationIdAsync(string email, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/verify-registration")
          .withParameter("email", email)
          .withParameter("sendVerifyPasswordEmail", false)
          .withParameter("applicationId", applicationId)
          .withMethod("Put")
          .goAsync<VerifyRegistrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TwoFactorRecoveryCodeResponse>> GenerateTwoFactorRecoveryCodesAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/two-factor/recovery-code")
          .withUriSegment(userId)
          .withMethod("Post")
          .goAsync<TwoFactorRecoveryCodeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<SecretResponse>> GenerateTwoFactorSecretAsync() {
      return buildClient()
          .withUri("/api/two-factor/secret")
          .withMethod("Get")
          .goAsync<SecretResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<SecretResponse>> GenerateTwoFactorSecretUsingJWTAsync(string encodedJWT) {
      return buildAnonymousClient()
          .withUri("/api/two-factor/secret")
          .withAuthorization("Bearer " + encodedJWT)
          .withMethod("Get")
          .goAsync<SecretResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginResponse>> IdentityProviderLoginAsync(IdentityProviderLoginRequest request) {
      return buildAnonymousClient()
          .withUri("/api/identity-provider/login")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<KeyResponse>> ImportKeyAsync(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key/import")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<KeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> ImportRefreshTokensAsync(RefreshTokenImportRequest request) {
      return buildClient()
          .withUri("/api/user/refresh-token/import")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> ImportUsersAsync(ImportRequest request) {
      return buildClient()
          .withUri("/api/user/import")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IntrospectResponse>> IntrospectAccessTokenAsync(string client_id, string token) {
      var body = new Dictionary<string, string> {
          { "client_id", client_id },
          { "token", token },
      };
      return buildAnonymousClient()
          .withUri("/oauth2/introspect")
          .withFormData(new FormUrlEncodedContent(body))
          .withMethod("Post")
          .goAsync<IntrospectResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IssueResponse>> IssueJWTAsync(Guid? applicationId, string encodedJWT, string refreshToken) {
      return buildAnonymousClient()
          .withUri("/api/jwt/issue")
          .withAuthorization("Bearer " + encodedJWT)
          .withParameter("applicationId", applicationId)
          .withParameter("refreshToken", refreshToken)
          .withMethod("Get")
          .goAsync<IssueResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginResponse>> LoginAsync(LoginRequest request) {
      return buildClient()
          .withUri("/api/login")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginResponse>> LoginPingAsync(Guid? userId, Guid? applicationId, string callerIPAddress) {
      return buildClient()
          .withUri("/api/login")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withParameter("ipAddress", callerIPAddress)
          .withMethod("Put")
          .goAsync<LoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginResponse>> LoginPingWithRequestAsync(LoginPingRequest request) {
      return buildClient()
          .withUri("/api/login")
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<LoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> LogoutAsync(bool? global, string refreshToken) {
      return buildAnonymousClient()
          .withUri("/api/logout")
          .withParameter("global", global)
          .withParameter("refreshToken", refreshToken)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> LogoutWithRequestAsync(LogoutRequest request) {
      return buildAnonymousClient()
          .withUri("/api/logout")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LookupResponse>> LookupIdentityProviderAsync(string domain) {
      return buildClient()
          .withUri("/api/identity-provider/lookup")
          .withParameter("domain", domain)
          .withMethod("Get")
          .goAsync<LookupResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ActionResponse>> ModifyActionAsync(Guid? actionId, ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginResponse>> PasswordlessLoginAsync(PasswordlessLoginRequest request) {
      return buildAnonymousClient()
          .withUri("/api/passwordless/login")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<APIKeyResponse>> PatchAPIKeyAsync(Guid? keyId, APIKeyRequest request) {
      return buildClient()
          .withUri("/api/api-key")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<APIKeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> PatchApplicationAsync(Guid? applicationId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> PatchApplicationRoleAsync(Guid? applicationId, Guid? roleId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConnectorResponse>> PatchConnectorAsync(Guid? connectorId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/connector")
          .withUriSegment(connectorId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ConnectorResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConsentResponse>> PatchConsentAsync(Guid? consentId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EmailTemplateResponse>> PatchEmailTemplateAsync(Guid? emailTemplateId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<EmailTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityTypeResponse>> PatchEntityTypeAsync(Guid? entityTypeId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/entity/type")
          .withUriSegment(entityTypeId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<EntityTypeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<GroupResponse>> PatchGroupAsync(Guid? groupId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<GroupResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderResponse>> PatchIdentityProviderAsync(Guid? identityProviderId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<IdentityProviderResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IntegrationResponse>> PatchIntegrationsAsync(IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/integration")
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<IntegrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LambdaResponse>> PatchLambdaAsync(Guid? lambdaId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<LambdaResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessageTemplateResponse>> PatchMessageTemplateAsync(Guid? messageTemplateId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/message/template")
          .withUriSegment(messageTemplateId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<MessageTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessengerResponse>> PatchMessengerAsync(Guid? messengerId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/messenger")
          .withUriSegment(messengerId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<MessengerResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RegistrationResponse>> PatchRegistrationAsync(Guid? userId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<RegistrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<SystemConfigurationResponse>> PatchSystemConfigurationAsync(IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/system-configuration")
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<SystemConfigurationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TenantResponse>> PatchTenantAsync(Guid? tenantId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<TenantResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ThemeResponse>> PatchThemeAsync(Guid? themeId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ThemeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> PatchUserAsync(Guid? userId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionResponse>> PatchUserActionAsync(Guid? userActionId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<UserActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionReasonResponse>> PatchUserActionReasonAsync(Guid? userActionReasonId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<UserActionReasonResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserConsentResponse>> PatchUserConsentAsync(Guid? userConsentId, IDictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<UserConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> ReactivateApplicationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> ReactivateUserAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionResponse>> ReactivateUserActionAsync(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .goAsync<UserActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginResponse>> ReconcileJWTAsync(IdentityProviderLoginRequest request) {
      return buildAnonymousClient()
          .withUri("/api/jwt/reconcile")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RefreshEntitySearchIndexAsync() {
      return buildClient()
          .withUri("/api/entity/search")
          .withMethod("Put")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RefreshUserSearchIndexAsync() {
      return buildClient()
          .withUri("/api/user/search")
          .withMethod("Put")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RegenerateReactorKeysAsync() {
      return buildClient()
          .withUri("/api/reactor")
          .withMethod("Put")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RegistrationResponse>> RegisterAsync(Guid? userId, RegistrationRequest request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RegistrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> ReindexAsync(ReindexRequest request) {
      return buildClient()
          .withUri("/api/system/reindex")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RemoveUserFromFamilyAsync(Guid? familyId, Guid? userId) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withUriSegment(userId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<VerifyEmailResponse>> ResendEmailVerificationAsync(string email) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withParameter("email", email)
          .withMethod("Put")
          .goAsync<VerifyEmailResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<VerifyEmailResponse>> ResendEmailVerificationWithApplicationTemplateAsync(Guid? applicationId, string email) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withParameter("applicationId", applicationId)
          .withParameter("email", email)
          .withMethod("Put")
          .goAsync<VerifyEmailResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<VerifyRegistrationResponse>> ResendRegistrationVerificationAsync(string email, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/verify-registration")
          .withParameter("email", email)
          .withParameter("applicationId", applicationId)
          .withMethod("Put")
          .goAsync<VerifyRegistrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<APIKeyResponse>> RetrieveAPIKeyAsync(Guid? keyId) {
      return buildClient()
          .withUri("/api/api-key")
          .withUriSegment(keyId)
          .withMethod("Get")
          .goAsync<APIKeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ActionResponse>> RetrieveActionAsync(Guid? actionId) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ActionResponse>> RetrieveActionsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ActionResponse>> RetrieveActionsPreventingLoginAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("preventingLogin", true)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ActionResponse>> RetrieveActiveActionsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("active", true)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> RetrieveApplicationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withMethod("Get")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> RetrieveApplicationsAsync() {
      return buildClient()
          .withUri("/api/application")
          .withMethod("Get")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<AuditLogResponse>> RetrieveAuditLogAsync(int? auditLogId) {
      return buildClient()
          .withUri("/api/system/audit-log")
          .withUriSegment(auditLogId)
          .withMethod("Get")
          .goAsync<AuditLogResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConnectorResponse>> RetrieveConnectorAsync(Guid? connectorId) {
      return buildClient()
          .withUri("/api/connector")
          .withUriSegment(connectorId)
          .withMethod("Get")
          .goAsync<ConnectorResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConnectorResponse>> RetrieveConnectorsAsync() {
      return buildClient()
          .withUri("/api/connector")
          .withMethod("Get")
          .goAsync<ConnectorResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConsentResponse>> RetrieveConsentAsync(Guid? consentId) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withMethod("Get")
          .goAsync<ConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConsentResponse>> RetrieveConsentsAsync() {
      return buildClient()
          .withUri("/api/consent")
          .withMethod("Get")
          .goAsync<ConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<DailyActiveUserReportResponse>> RetrieveDailyActiveReportAsync(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/daily-active-user")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<DailyActiveUserReportResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EmailTemplateResponse>> RetrieveEmailTemplateAsync(Guid? emailTemplateId) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withMethod("Get")
          .goAsync<EmailTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PreviewResponse>> RetrieveEmailTemplatePreviewAsync(PreviewRequest request) {
      return buildClient()
          .withUri("/api/email/template/preview")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<PreviewResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EmailTemplateResponse>> RetrieveEmailTemplatesAsync() {
      return buildClient()
          .withUri("/api/email/template")
          .withMethod("Get")
          .goAsync<EmailTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityResponse>> RetrieveEntityAsync(Guid? entityId) {
      return buildClient()
          .withUri("/api/entity")
          .withUriSegment(entityId)
          .withMethod("Get")
          .goAsync<EntityResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityGrantResponse>> RetrieveEntityGrantAsync(Guid? entityId, Guid? recipientEntityId, Guid? userId) {
      return buildClient()
          .withUri("/api/entity")
          .withUriSegment(entityId)
          .withUriSegment("grant")
          .withParameter("recipientEntityId", recipientEntityId)
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<EntityGrantResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityTypeResponse>> RetrieveEntityTypeAsync(Guid? entityTypeId) {
      return buildClient()
          .withUri("/api/entity/type")
          .withUriSegment(entityTypeId)
          .withMethod("Get")
          .goAsync<EntityTypeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityTypeResponse>> RetrieveEntityTypesAsync() {
      return buildClient()
          .withUri("/api/entity/type")
          .withMethod("Get")
          .goAsync<EntityTypeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EventLogResponse>> RetrieveEventLogAsync(int? eventLogId) {
      return buildClient()
          .withUri("/api/system/event-log")
          .withUriSegment(eventLogId)
          .withMethod("Get")
          .goAsync<EventLogResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FamilyResponse>> RetrieveFamiliesAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/family")
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<FamilyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FamilyResponse>> RetrieveFamilyMembersByFamilyIdAsync(Guid? familyId) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withMethod("Get")
          .goAsync<FamilyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FormResponse>> RetrieveFormAsync(Guid? formId) {
      return buildClient()
          .withUri("/api/form")
          .withUriSegment(formId)
          .withMethod("Get")
          .goAsync<FormResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FormFieldResponse>> RetrieveFormFieldAsync(Guid? fieldId) {
      return buildClient()
          .withUri("/api/form/field")
          .withUriSegment(fieldId)
          .withMethod("Get")
          .goAsync<FormFieldResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FormFieldResponse>> RetrieveFormFieldsAsync() {
      return buildClient()
          .withUri("/api/form/field")
          .withMethod("Get")
          .goAsync<FormFieldResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FormResponse>> RetrieveFormsAsync() {
      return buildClient()
          .withUri("/api/form")
          .withMethod("Get")
          .goAsync<FormResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<GroupResponse>> RetrieveGroupAsync(Guid? groupId) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withMethod("Get")
          .goAsync<GroupResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<GroupResponse>> RetrieveGroupsAsync() {
      return buildClient()
          .withUri("/api/group")
          .withMethod("Get")
          .goAsync<GroupResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IPAccessControlListResponse>> RetrieveIPAccessControlListAsync(Guid? ipAccessControlListId) {
      return buildClient()
          .withUri("/api/ip-acl")
          .withUriSegment(ipAccessControlListId)
          .withMethod("Get")
          .goAsync<IPAccessControlListResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderResponse>> RetrieveIdentityProviderAsync(Guid? identityProviderId) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withMethod("Get")
          .goAsync<IdentityProviderResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderResponse>> RetrieveIdentityProviderByTypeAsync(IdentityProviderType type) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withParameter("type", type)
          .withMethod("Get")
          .goAsync<IdentityProviderResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderResponse>> RetrieveIdentityProvidersAsync() {
      return buildClient()
          .withUri("/api/identity-provider")
          .withMethod("Get")
          .goAsync<IdentityProviderResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ActionResponse>> RetrieveInactiveActionsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("active", false)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> RetrieveInactiveApplicationsAsync() {
      return buildClient()
          .withUri("/api/application")
          .withParameter("inactive", true)
          .withMethod("Get")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionResponse>> RetrieveInactiveUserActionsAsync() {
      return buildClient()
          .withUri("/api/user-action")
          .withParameter("inactive", true)
          .withMethod("Get")
          .goAsync<UserActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IntegrationResponse>> RetrieveIntegrationAsync() {
      return buildClient()
          .withUri("/api/integration")
          .withMethod("Get")
          .goAsync<IntegrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeyAsync(string keyId) {
      return buildAnonymousClient()
          .withUri("/api/jwt/public-key")
          .withParameter("kid", keyId)
          .withMethod("Get")
          .goAsync<PublicKeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeyByApplicationIdAsync(string applicationId) {
      return buildAnonymousClient()
          .withUri("/api/jwt/public-key")
          .withParameter("applicationId", applicationId)
          .withMethod("Get")
          .goAsync<PublicKeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeysAsync() {
      return buildAnonymousClient()
          .withUri("/api/jwt/public-key")
          .withMethod("Get")
          .goAsync<PublicKeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<JWKSResponse>> RetrieveJsonWebKeySetAsync() {
      return buildAnonymousClient()
          .withUri("/.well-known/jwks.json")
          .withMethod("Get")
          .goAsync<JWKSResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<KeyResponse>> RetrieveKeyAsync(Guid? keyId) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyId)
          .withMethod("Get")
          .goAsync<KeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<KeyResponse>> RetrieveKeysAsync() {
      return buildClient()
          .withUri("/api/key")
          .withMethod("Get")
          .goAsync<KeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LambdaResponse>> RetrieveLambdaAsync(Guid? lambdaId) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withMethod("Get")
          .goAsync<LambdaResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LambdaResponse>> RetrieveLambdasAsync() {
      return buildClient()
          .withUri("/api/lambda")
          .withMethod("Get")
          .goAsync<LambdaResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LambdaResponse>> RetrieveLambdasByTypeAsync(LambdaType type) {
      return buildClient()
          .withUri("/api/lambda")
          .withParameter("type", type)
          .withMethod("Get")
          .goAsync<LambdaResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginReportResponse>> RetrieveLoginReportAsync(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/login")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<LoginReportResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessageTemplateResponse>> RetrieveMessageTemplateAsync(Guid? messageTemplateId) {
      return buildClient()
          .withUri("/api/message/template")
          .withUriSegment(messageTemplateId)
          .withMethod("Get")
          .goAsync<MessageTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PreviewMessageTemplateResponse>> RetrieveMessageTemplatePreviewAsync(PreviewMessageTemplateRequest request) {
      return buildClient()
          .withUri("/api/message/template/preview")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<PreviewMessageTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessageTemplateResponse>> RetrieveMessageTemplatesAsync() {
      return buildClient()
          .withUri("/api/message/template")
          .withMethod("Get")
          .goAsync<MessageTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessengerResponse>> RetrieveMessengerAsync(Guid? messengerId) {
      return buildClient()
          .withUri("/api/messenger")
          .withUriSegment(messengerId)
          .withMethod("Get")
          .goAsync<MessengerResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessengerResponse>> RetrieveMessengersAsync() {
      return buildClient()
          .withUri("/api/messenger")
          .withMethod("Get")
          .goAsync<MessengerResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MonthlyActiveUserReportResponse>> RetrieveMonthlyActiveReportAsync(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/monthly-active-user")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<MonthlyActiveUserReportResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<OAuthConfigurationResponse>> RetrieveOauthConfigurationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("oauth-configuration")
          .withMethod("Get")
          .goAsync<OAuthConfigurationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<OpenIdConfiguration>> RetrieveOpenIdConfigurationAsync() {
      return buildAnonymousClient()
          .withUri("/.well-known/openid-configuration")
          .withMethod("Get")
          .goAsync<OpenIdConfiguration>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PasswordValidationRulesResponse>> RetrievePasswordValidationRulesAsync() {
      return buildAnonymousClient()
          .withUri("/api/tenant/password-validation-rules")
          .withMethod("Get")
          .goAsync<PasswordValidationRulesResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PasswordValidationRulesResponse>> RetrievePasswordValidationRulesWithTenantIdAsync(Guid? tenantId) {
      return buildAnonymousClient()
          .withUri("/api/tenant/password-validation-rules")
          .withUriSegment(tenantId)
          .withMethod("Get")
          .goAsync<PasswordValidationRulesResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PendingResponse>> RetrievePendingChildrenAsync(string parentEmail) {
      return buildClient()
          .withUri("/api/user/family/pending")
          .withParameter("parentEmail", parentEmail)
          .withMethod("Get")
          .goAsync<PendingResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ReactorMetricsResponse>> RetrieveReactorMetricsAsync() {
      return buildClient()
          .withUri("/api/reactor/metrics")
          .withMethod("Get")
          .goAsync<ReactorMetricsResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ReactorResponse>> RetrieveReactorStatusAsync() {
      return buildClient()
          .withUri("/api/reactor")
          .withMethod("Get")
          .goAsync<ReactorResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RecentLoginResponse>> RetrieveRecentLoginsAsync(int? offset, int? limit) {
      return buildClient()
          .withUri("/api/user/recent-login")
          .withParameter("offset", offset)
          .withParameter("limit", limit)
          .withMethod("Get")
          .goAsync<RecentLoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RefreshTokenResponse>> RetrieveRefreshTokenByIdAsync(Guid? tokenId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withUriSegment(tokenId)
          .withMethod("Get")
          .goAsync<RefreshTokenResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RefreshTokenResponse>> RetrieveRefreshTokensAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<RefreshTokenResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RegistrationResponse>> RetrieveRegistrationAsync(Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withMethod("Get")
          .goAsync<RegistrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RegistrationReportResponse>> RetrieveRegistrationReportAsync(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/registration")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<RegistrationReportResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RetrieveReindexStatusAsync() {
      return buildClient()
          .withUri("/api/system/reindex")
          .withMethod("Get")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<SystemConfigurationResponse>> RetrieveSystemConfigurationAsync() {
      return buildClient()
          .withUri("/api/system-configuration")
          .withMethod("Get")
          .goAsync<SystemConfigurationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TenantResponse>> RetrieveTenantAsync(Guid? tenantId) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withMethod("Get")
          .goAsync<TenantResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TenantResponse>> RetrieveTenantsAsync() {
      return buildClient()
          .withUri("/api/tenant")
          .withMethod("Get")
          .goAsync<TenantResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ThemeResponse>> RetrieveThemeAsync(Guid? themeId) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withMethod("Get")
          .goAsync<ThemeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ThemeResponse>> RetrieveThemesAsync() {
      return buildClient()
          .withUri("/api/theme")
          .withMethod("Get")
          .goAsync<ThemeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TotalsReportResponse>> RetrieveTotalReportAsync() {
      return buildClient()
          .withUri("/api/report/totals")
          .withMethod("Get")
          .goAsync<TotalsReportResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TwoFactorRecoveryCodeResponse>> RetrieveTwoFactorRecoveryCodesAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/two-factor/recovery-code")
          .withUriSegment(userId)
          .withMethod("Get")
          .goAsync<TwoFactorRecoveryCodeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TwoFactorStatusResponse>> RetrieveTwoFactorStatusAsync(Guid? userId, Guid? applicationId, string twoFactorTrustId) {
      return buildClient()
          .withUri("/api/two-factor/status")
          .withParameter("userId", userId)
          .withParameter("applicationId", applicationId)
          .withUriSegment(twoFactorTrustId)
          .withMethod("Get")
          .goAsync<TwoFactorStatusResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> RetrieveUserAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionResponse>> RetrieveUserActionAsync(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withMethod("Get")
          .goAsync<UserActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionReasonResponse>> RetrieveUserActionReasonAsync(Guid? userActionReasonId) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withMethod("Get")
          .goAsync<UserActionReasonResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionReasonResponse>> RetrieveUserActionReasonsAsync() {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withMethod("Get")
          .goAsync<UserActionReasonResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionResponse>> RetrieveUserActionsAsync() {
      return buildClient()
          .withUri("/api/user-action")
          .withMethod("Get")
          .goAsync<UserActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> RetrieveUserByChangePasswordIdAsync(string changePasswordId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("changePasswordId", changePasswordId)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> RetrieveUserByEmailAsync(string email) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("email", email)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> RetrieveUserByLoginIdAsync(string loginId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("loginId", loginId)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> RetrieveUserByUsernameAsync(string username) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("username", username)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> RetrieveUserByVerificationIdAsync(string verificationId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("verificationId", verificationId)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserCommentResponse>> RetrieveUserCommentsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/comment")
          .withUriSegment(userId)
          .withMethod("Get")
          .goAsync<UserCommentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserConsentResponse>> RetrieveUserConsentAsync(Guid? userConsentId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withMethod("Get")
          .goAsync<UserConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserConsentResponse>> RetrieveUserConsentsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<UserConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> RetrieveUserInfoFromAccessTokenAsync(string encodedJWT) {
      return buildAnonymousClient()
          .withUri("/oauth2/userinfo")
          .withAuthorization("Bearer " + encodedJWT)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderLinkResponse>> RetrieveUserLinkAsync(Guid? identityProviderId, string identityProviderUserId, Guid? userId) {
      return buildClient()
          .withUri("/api/identity-provider/link")
          .withParameter("identityProviderId", identityProviderId)
          .withParameter("identityProviderUserId", identityProviderUserId)
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<IdentityProviderLinkResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderLinkResponse>> RetrieveUserLinksByUserIdAsync(Guid? identityProviderId, Guid? userId) {
      return buildClient()
          .withUri("/api/identity-provider/link")
          .withParameter("identityProviderId", identityProviderId)
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<IdentityProviderLinkResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginReportResponse>> RetrieveUserLoginReportAsync(Guid? applicationId, Guid? userId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/login")
          .withParameter("applicationId", applicationId)
          .withParameter("userId", userId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<LoginReportResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginReportResponse>> RetrieveUserLoginReportByLoginIdAsync(Guid? applicationId, string loginId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/login")
          .withParameter("applicationId", applicationId)
          .withParameter("loginId", loginId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<LoginReportResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RecentLoginResponse>> RetrieveUserRecentLoginsAsync(Guid? userId, int? offset, int? limit) {
      return buildClient()
          .withUri("/api/user/recent-login")
          .withParameter("userId", userId)
          .withParameter("offset", offset)
          .withParameter("limit", limit)
          .withMethod("Get")
          .goAsync<RecentLoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> RetrieveUserUsingJWTAsync(string encodedJWT) {
      return buildAnonymousClient()
          .withUri("/api/user")
          .withAuthorization("Bearer " + encodedJWT)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<VersionResponse>> RetrieveVersionAsync() {
      return buildClient()
          .withUri("/api/system/version")
          .withMethod("Get")
          .goAsync<VersionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<WebhookResponse>> RetrieveWebhookAsync(Guid? webhookId) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withMethod("Get")
          .goAsync<WebhookResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<WebhookResponse>> RetrieveWebhooksAsync() {
      return buildClient()
          .withUri("/api/webhook")
          .withMethod("Get")
          .goAsync<WebhookResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RevokeRefreshTokenAsync(string token, Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("token", token)
          .withParameter("userId", userId)
          .withParameter("applicationId", applicationId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RevokeRefreshTokenByIdAsync(Guid? tokenId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withUriSegment(tokenId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RevokeRefreshTokenByTokenAsync(string token) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("token", token)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RevokeRefreshTokensByApplicationIdAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("applicationId", applicationId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RevokeRefreshTokensByUserIdAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("userId", userId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RevokeRefreshTokensByUserIdForApplicationAsync(Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("userId", userId)
          .withParameter("applicationId", applicationId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RevokeRefreshTokensWithRequestAsync(RefreshTokenRevokeRequest request) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> RevokeUserConsentAsync(Guid? userConsentId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<AuditLogSearchResponse>> SearchAuditLogsAsync(AuditLogSearchRequest request) {
      return buildClient()
          .withUri("/api/system/audit-log/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<AuditLogSearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntitySearchResponse>> SearchEntitiesAsync(EntitySearchRequest request) {
      return buildClient()
          .withUri("/api/entity/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EntitySearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntitySearchResponse>> SearchEntitiesByIdsAsync(List<string> ids) {
      return buildClient()
          .withUri("/api/entity/search")
          .withParameter("ids", ids)
          .withMethod("Get")
          .goAsync<EntitySearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityGrantSearchResponse>> SearchEntityGrantsAsync(EntityGrantSearchRequest request) {
      return buildClient()
          .withUri("/api/entity/grant/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EntityGrantSearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityTypeSearchResponse>> SearchEntityTypesAsync(EntityTypeSearchRequest request) {
      return buildClient()
          .withUri("/api/entity/type/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EntityTypeSearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EventLogSearchResponse>> SearchEventLogsAsync(EventLogSearchRequest request) {
      return buildClient()
          .withUri("/api/system/event-log/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EventLogSearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<GroupMemberSearchResponse>> SearchGroupMembersAsync(GroupMemberSearchRequest request) {
      return buildClient()
          .withUri("/api/group/member/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<GroupMemberSearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IPAccessControlListSearchResponse>> SearchIPAccessControlListsAsync(IPAccessControlListSearchRequest request) {
      return buildClient()
          .withUri("/api/ip-acl/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<IPAccessControlListSearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginRecordSearchResponse>> SearchLoginRecordsAsync(LoginRecordSearchRequest request) {
      return buildClient()
          .withUri("/api/system/login-record/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginRecordSearchResponse>();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to SearchUsersByIdsAsync, use that method instead.")]
    public Task<ClientResponse<SearchResponse>> SearchUsersAsync(List<string> ids) {
      return buildClient()
          .withUri("/api/user/search")
          .withParameter("ids", ids)
          .withMethod("Get")
          .goAsync<SearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<SearchResponse>> SearchUsersByIdsAsync(List<string> ids) {
      return buildClient()
          .withUri("/api/user/search")
          .withParameter("ids", ids)
          .withMethod("Get")
          .goAsync<SearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<SearchResponse>> SearchUsersByQueryAsync(SearchRequest request) {
      return buildClient()
          .withUri("/api/user/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<SearchResponse>();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to SearchUsersByQueryAsync, use that method instead.")]
    public Task<ClientResponse<SearchResponse>> SearchUsersByQueryStringAsync(SearchRequest request) {
      return buildClient()
          .withUri("/api/user/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<SearchResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<SendResponse>> SendEmailAsync(Guid? emailTemplateId, SendRequest request) {
      return buildClient()
          .withUri("/api/email/send")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<SendResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> SendFamilyRequestEmailAsync(FamilyEmailRequest request) {
      return buildClient()
          .withUri("/api/user/family/request")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> SendPasswordlessCodeAsync(PasswordlessSendRequest request) {
      return buildAnonymousClient()
          .withUri("/api/passwordless/send")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to SendTwoFactorCodeForEnableDisableAsync, use that method instead.")]
    public Task<ClientResponse<RESTVoid>> SendTwoFactorCodeAsync(TwoFactorSendRequest request) {
      return buildClient()
          .withUri("/api/two-factor/send")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> SendTwoFactorCodeForEnableDisableAsync(TwoFactorSendRequest request) {
      return buildClient()
          .withUri("/api/two-factor/send")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to SendTwoFactorCodeForLoginUsingMethodAsync, use that method instead.")]
    public Task<ClientResponse<RESTVoid>> SendTwoFactorCodeForLoginAsync(string twoFactorId) {
      return buildAnonymousClient()
          .withUri("/api/two-factor/send")
          .withUriSegment(twoFactorId)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> SendTwoFactorCodeForLoginUsingMethodAsync(string twoFactorId, TwoFactorSendRequest request) {
      return buildAnonymousClient()
          .withUri("/api/two-factor/send")
          .withUriSegment(twoFactorId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderStartLoginResponse>> StartIdentityProviderLoginAsync(IdentityProviderStartLoginRequest request) {
      return buildClient()
          .withUri("/api/identity-provider/start")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<IdentityProviderStartLoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<PasswordlessStartResponse>> StartPasswordlessLoginAsync(PasswordlessStartRequest request) {
      return buildClient()
          .withUri("/api/passwordless/start")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<PasswordlessStartResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TwoFactorStartResponse>> StartTwoFactorLoginAsync(TwoFactorStartRequest request) {
      return buildClient()
          .withUri("/api/two-factor/start")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<TwoFactorStartResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LoginResponse>> TwoFactorLoginAsync(TwoFactorLoginRequest request) {
      return buildAnonymousClient()
          .withUri("/api/two-factor/login")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<APIKeyResponse>> UpdateAPIKeyAsync(Guid? apiKeyId, APIKeyRequest request) {
      return buildClient()
          .withUri("/api/api-key")
          .withUriSegment(apiKeyId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<APIKeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> UpdateApplicationAsync(Guid? applicationId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ApplicationResponse>> UpdateApplicationRoleAsync(Guid? applicationId, Guid? roleId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ApplicationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConnectorResponse>> UpdateConnectorAsync(Guid? connectorId, ConnectorRequest request) {
      return buildClient()
          .withUri("/api/connector")
          .withUriSegment(connectorId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ConnectorResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ConsentResponse>> UpdateConsentAsync(Guid? consentId, ConsentRequest request) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EmailTemplateResponse>> UpdateEmailTemplateAsync(Guid? emailTemplateId, EmailTemplateRequest request) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<EmailTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityResponse>> UpdateEntityAsync(Guid? entityId, EntityRequest request) {
      return buildClient()
          .withUri("/api/entity")
          .withUriSegment(entityId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<EntityResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityTypeResponse>> UpdateEntityTypeAsync(Guid? entityTypeId, EntityTypeRequest request) {
      return buildClient()
          .withUri("/api/entity/type")
          .withUriSegment(entityTypeId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<EntityTypeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<EntityTypeResponse>> UpdateEntityTypePermissionAsync(Guid? entityTypeId, Guid? permissionId, EntityTypeRequest request) {
      return buildClient()
          .withUri("/api/entity/type")
          .withUriSegment(entityTypeId)
          .withUriSegment("permission")
          .withUriSegment(permissionId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<EntityTypeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FormResponse>> UpdateFormAsync(Guid? formId, FormRequest request) {
      return buildClient()
          .withUri("/api/form")
          .withUriSegment(formId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<FormResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<FormFieldResponse>> UpdateFormFieldAsync(Guid? fieldId, FormFieldRequest request) {
      return buildClient()
          .withUri("/api/form/field")
          .withUriSegment(fieldId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<FormFieldResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<GroupResponse>> UpdateGroupAsync(Guid? groupId, GroupRequest request) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<GroupResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MemberResponse>> UpdateGroupMembersAsync(MemberRequest request) {
      return buildClient()
          .withUri("/api/group/member")
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<MemberResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IPAccessControlListResponse>> UpdateIPAccessControlListAsync(Guid? accessControlListId, IPAccessControlListRequest request) {
      return buildClient()
          .withUri("/api/ip-acl")
          .withUriSegment(accessControlListId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<IPAccessControlListResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IdentityProviderResponse>> UpdateIdentityProviderAsync(Guid? identityProviderId, IdentityProviderRequest request) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<IdentityProviderResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<IntegrationResponse>> UpdateIntegrationsAsync(IntegrationRequest request) {
      return buildClient()
          .withUri("/api/integration")
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<IntegrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<KeyResponse>> UpdateKeyAsync(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<KeyResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<LambdaResponse>> UpdateLambdaAsync(Guid? lambdaId, LambdaRequest request) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<LambdaResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessageTemplateResponse>> UpdateMessageTemplateAsync(Guid? messageTemplateId, MessageTemplateRequest request) {
      return buildClient()
          .withUri("/api/message/template")
          .withUriSegment(messageTemplateId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<MessageTemplateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<MessengerResponse>> UpdateMessengerAsync(Guid? messengerId, MessengerRequest request) {
      return buildClient()
          .withUri("/api/messenger")
          .withUriSegment(messengerId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<MessengerResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RegistrationResponse>> UpdateRegistrationAsync(Guid? userId, RegistrationRequest request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<RegistrationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<SystemConfigurationResponse>> UpdateSystemConfigurationAsync(SystemConfigurationRequest request) {
      return buildClient()
          .withUri("/api/system-configuration")
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<SystemConfigurationResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<TenantResponse>> UpdateTenantAsync(Guid? tenantId, TenantRequest request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<TenantResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ThemeResponse>> UpdateThemeAsync(Guid? themeId, ThemeRequest request) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ThemeResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserResponse>> UpdateUserAsync(Guid? userId, UserRequest request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<UserResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionResponse>> UpdateUserActionAsync(Guid? userActionId, UserActionRequest request) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<UserActionResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserActionReasonResponse>> UpdateUserActionReasonAsync(Guid? userActionReasonId, UserActionReasonRequest request) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<UserActionReasonResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<UserConsentResponse>> UpdateUserConsentAsync(Guid? userConsentId, UserConsentRequest request) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<UserConsentResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<WebhookResponse>> UpdateWebhookAsync(Guid? webhookId, WebhookRequest request) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<WebhookResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> UpsertEntityGrantAsync(Guid? entityId, EntityGrantRequest request) {
      return buildClient()
          .withUri("/api/entity")
          .withUriSegment(entityId)
          .withUriSegment("grant")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> ValidateDeviceAsync(string user_code, string client_id) {
      return buildAnonymousClient()
          .withUri("/oauth2/device/validate")
          .withParameter("user_code", user_code)
          .withParameter("client_id", client_id)
          .withMethod("Get")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<ValidateResponse>> ValidateJWTAsync(string encodedJWT) {
      return buildAnonymousClient()
          .withUri("/api/jwt/validate")
          .withAuthorization("Bearer " + encodedJWT)
          .withMethod("Get")
          .goAsync<ValidateResponse>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<JWTVendResponse>> VendJWTAsync(JWTVendRequest request) {
      return buildClient()
          .withUri("/api/jwt/vend")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<JWTVendResponse>();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to VerifyEmailAddressAsync and changed to take a JSON request body, use that method instead.")]
    public Task<ClientResponse<RESTVoid>> VerifyEmailAsync(string verificationId) {
      return buildAnonymousClient()
          .withUri("/api/user/verify-email")
          .withUriSegment(verificationId)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> VerifyEmailAddressAsync(VerifyEmailRequest request) {
      return buildAnonymousClient()
          .withUri("/api/user/verify-email")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> VerifyEmailAddressByUserIdAsync(VerifyEmailRequest request) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to VerifyUserRegistrationAsync and changed to take a JSON request body, use that method instead.")]
    public Task<ClientResponse<RESTVoid>> VerifyRegistrationAsync(string verificationId) {
      return buildAnonymousClient()
          .withUri("/api/user/verify-registration")
          .withUriSegment(verificationId)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }

    /// <inheritdoc/>
    public Task<ClientResponse<RESTVoid>> VerifyUserRegistrationAsync(VerifyRegistrationRequest request) {
      return buildAnonymousClient()
          .withUri("/api/user/verify-registration")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
  }

  internal class DefaultRESTClientBuilder : IRESTClientBuilder {
    public IRESTClient build(string host) {
      return new DefaultRESTClient(host);
    }
  }
}
