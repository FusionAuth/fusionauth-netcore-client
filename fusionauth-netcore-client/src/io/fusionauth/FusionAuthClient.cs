/*
 * Copyright (c) 2018-2019, FusionAuth, All Rights Reserved
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
using io.fusionauth.domain;
using io.fusionauth.domain.api;
using io.fusionauth.domain.api.email;
using io.fusionauth.domain.api.identityProvider;
using io.fusionauth.domain.api.jwt;
using io.fusionauth.domain.api.passwordless;
using io.fusionauth.domain.api.report;
using io.fusionauth.domain.api.twoFactor;
using io.fusionauth.domain.api.user;

namespace io.fusionauth {
  public class FusionAuthClient {
    public readonly string apiKey;

    public readonly string host;

    public readonly string tenantId;

    public IRESTClientBuilder clientBuilder;

    public FusionAuthClient(string apiKey, string host, string tenantId = null) {
      this.apiKey = apiKey;
      this.host = host;
      this.tenantId = tenantId;

      clientBuilder = new DefaultRESTClientBuilder();
    }

    public IRESTClient buildClient() {
      var client = clientBuilder.build(host)
                                .withAuthorization(apiKey);

      if (tenantId != null) {
        client.withHeader("X-FusionAuth-TenantId", tenantId);
      }

      return client;
    }

    /**
     * Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
     * "actioner". Both user ids are required. You pass the actionee's user id into the method and the actioner's is put into the
     * request object.
     *
     * @param actioneeUserId The actionee's user id.
     * @param request The action request that includes all of the information about the action being taken including
     * the id of the action, any options and the duration (if applicable).
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ActionResponse> ActionUser(Guid? actioneeUserId, ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actioneeUserId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<ActionResponse>();
    }
    /**
     * Adds a user to an existing family. The family id must be specified.
     *
     * @param familyId The id of the family.
     * @param request The request object that contains all of the information used to determine which user to add to the family.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<FamilyResponse> AddUserToFamily(Guid? familyId, FamilyRequest request) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<FamilyResponse>();
    }
    /**
     * Cancels the user action.
     *
     * @param actionId The action id of the action to cancel.
     * @param request The action request that contains the information about the cancellation.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ActionResponse> CancelAction(Guid? actionId, ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withJSONBody(request)
          .withMethod("Delete")
          .go<ActionResponse>();
    }
    /**
     * Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
     * and they clicked on a link to reset their password.
     *
     * @param changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
     * @param request The change password request that contains all of the information used to change the password.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ChangePasswordResponse> ChangePassword(string changePasswordId, ChangePasswordRequest request) {
      return buildClient()
          .withUri("/api/user/change-password")
          .withUriSegment(changePasswordId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<ChangePasswordResponse>();
    }
    /**
     * Changes a user's password using their identity (login id and password). Using a loginId instead of the changePasswordId
     * bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
     * method.
     *
     * @param request The change password request that contains all of the information used to change the password.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> ChangePasswordByIdentity(ChangePasswordRequest request) {
      return buildClient()
          .withUri("/api/user/change-password")
          .withJSONBody(request)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Adds a comment to the user's account.
     *
     * @param request The request object that contains all of the information used to create the user comment.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> CommentOnUser(UserCommentRequest request) {
      return buildClient()
          .withUri("/api/user/comment")
          .withJSONBody(request)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
     *
     * @param applicationId (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the application.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ApplicationResponse> CreateApplication(Guid? applicationId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<ApplicationResponse>();
    }
    /**
     * Creates a new role for an application. You must specify the id of the application you are creating the role for.
     * You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
     *
     * @param applicationId The Id of the application to create the role on.
     * @param roleId (Optional) The Id of the role. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the application role.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ApplicationResponse> CreateApplicationRole(Guid? applicationId, Guid? roleId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<ApplicationResponse>();
    }
    /**
     * Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
     * make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
     * written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
     *
     * @param request The request object that contains all of the information used to create the audit log entry.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<AuditLogResponse> CreateAuditLog(AuditLogRequest request) {
      return buildClient()
          .withUri("/api/system/audit-log")
          .withJSONBody(request)
          .withMethod("Post")
          .go<AuditLogResponse>();
    }
    /**
     * Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
     *
     * @param consentId (Optional) The Id for the consent. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the consent.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ConsentResponse> CreateConsent(Guid? consentId, ConsentRequest request) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<ConsentResponse>();
    }
    /**
     * Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
     *
     * @param emailTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the email template.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<EmailTemplateResponse> CreateEmailTemplate(Guid? emailTemplateId, EmailTemplateRequest request) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<EmailTemplateResponse>();
    }
    /**
     * Creates a family with the user id in the request as the owner and sole member of the family. You can optionally specify an id for the
     * family, if not provided one will be generated.
     *
     * @param familyId (Optional) The id for the family. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the family.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<FamilyResponse> CreateFamily(Guid? familyId, FamilyRequest request) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<FamilyResponse>();
    }
    /**
     * Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
     *
     * @param groupId (Optional) The Id for the group. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the group.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<GroupResponse> CreateGroup(Guid? groupId, GroupRequest request) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<GroupResponse>();
    }
    /**
     * Creates a member in a group.
     *
     * @param request The request object that contains all of the information used to create the group member(s).
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<MemberResponse> CreateGroupMembers(MemberRequest request) {
      return buildClient()
          .withUri("/api/group/member")
          .withJSONBody(request)
          .withMethod("Post")
          .go<MemberResponse>();
    }
    /**
     * Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
     *
     * @param identityProviderId (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the identity provider.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<IdentityProviderResponse> CreateIdentityProvider(Guid? identityProviderId, IdentityProviderRequest request) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<IdentityProviderResponse>();
    }
    /**
     * Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
     *
     * @param lambdaId (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the lambda.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LambdaResponse> CreateLambda(Guid? lambdaId, LambdaRequest request) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<LambdaResponse>();
    }
    /**
     * Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
     *
     * @param tenantId (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the tenant.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<TenantResponse> CreateTenant(Guid? tenantId, TenantRequest request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<TenantResponse>();
    }
    /**
     * Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
     *
     * @param themeId (Optional) The Id for the theme. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the theme.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ThemeResponse> CreateTheme(Guid? themeId, ThemeRequest request) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<ThemeResponse>();
    }
    /**
     * Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
     *
     * @param userId (Optional) The Id for the user. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> CreateUser(Guid? userId, UserRequest request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<UserResponse>();
    }
    /**
     * Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
     * that the user action can be applied to any user.
     *
     * @param userActionId (Optional) The Id for the user action. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the user action.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionResponse> CreateUserAction(Guid? userActionId, UserActionRequest request) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<UserActionResponse>();
    }
    /**
     * Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
     * successfully. Anytime after that the user action reason can be used.
     *
     * @param userActionReasonId (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the user action reason.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionReasonResponse> CreateUserActionReason(Guid? userActionReasonId, UserActionReasonRequest request) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<UserActionReasonResponse>();
    }
    /**
     * Creates a single User consent.
     *
     * @param userConsentId (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.
     * @param request The request that contains the user consent information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserConsentResponse> CreateUserConsent(Guid? userConsentId, UserConsentRequest request) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<UserConsentResponse>();
    }
    /**
     * Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
     *
     * @param webhookId (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the webhook.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<WebhookResponse> CreateWebhook(Guid? webhookId, WebhookRequest request) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<WebhookResponse>();
    }
    /**
     * Deactivates the application with the given Id.
     *
     * @param applicationId The Id of the application to deactivate.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeactivateApplication(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deactivates the user with the given Id.
     *
     * @param userId The Id of the user to deactivate.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeactivateUser(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deactivates the user action with the given Id.
     *
     * @param userActionId The Id of the user action to deactivate.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeactivateUserAction(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deactivates the users with the given ids.
     *
     * @param userIds The ids of the users to deactivate.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeactivateUsers(List<string> userIds) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withParameter("userId", userIds)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
     * delete the application, any registrations for that application, metrics and reports for the application, all the
     * roles for the application, and any other data associated with the application. This operation could take a very
     * long time, depending on the amount of data in your database.
     *
     * @param applicationId The Id of the application to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteApplication(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
     * permanently removes the given role from all users that had it.
     *
     * @param applicationId The Id of the application to deactivate.
     * @param roleId The Id of the role to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteApplicationRole(Guid? applicationId, Guid? roleId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the consent for the given Id.
     *
     * @param consentId The Id of the consent to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteConsent(Guid? consentId) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the email template for the given Id.
     *
     * @param emailTemplateId The Id of the email template to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteEmailTemplate(Guid? emailTemplateId) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the group for the given Id.
     *
     * @param groupId The Id of the group to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteGroup(Guid? groupId) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Removes users as members of a group.
     *
     * @param request The member request that contains all of the information used to remove members to the group.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteGroupMembers(MemberDeleteRequest request) {
      return buildClient()
          .withUri("/api/group/member")
          .withJSONBody(request)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the identity provider for the given Id.
     *
     * @param identityProviderId The Id of the identity provider to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteIdentityProvider(Guid? identityProviderId) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the key for the given Id.
     *
     * @param keyOd The Id of the key to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteKey(Guid? keyOd) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyOd)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the lambda for the given Id.
     *
     * @param lambdaId The Id of the lambda to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteLambda(Guid? lambdaId) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the user registration for the given user and application.
     *
     * @param userId The Id of the user whose registration is being deleted.
     * @param applicationId The Id of the application to remove the registration for.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteRegistration(Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the tenant for the given Id.
     *
     * @param tenantId The Id of the tenant to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteTenant(Guid? tenantId) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the theme for the given Id.
     *
     * @param themeId The Id of the theme to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteTheme(Guid? themeId) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
     * with the user.
     *
     * @param userId The Id of the user to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteUser(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
     * the action being applied to any users.
     *
     * @param userActionId The Id of the user action to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteUserAction(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the user action reason for the given Id.
     *
     * @param userActionReasonId The Id of the user action reason to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteUserActionReason(Guid? userActionReasonId) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the users with the given ids.
     *
     * @param request The ids of the users to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteUsers(UserDeleteRequest request) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withJSONBody(request)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Deletes the webhook for the given Id.
     *
     * @param webhookId The Id of the webhook to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DeleteWebhook(Guid? webhookId) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Disable Two Factor authentication for a user.
     *
     * @param userId The Id of the User for which you're disabling Two Factor authentication.
     * @param code The Two Factor code used verify the the caller knows the Two Factor secret.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> DisableTwoFactor(Guid? userId, string code) {
      return buildClient()
          .withUri("/api/user/two-factor")
          .withParameter("userId", userId)
          .withParameter("code", code)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Enable Two Factor authentication for a user.
     *
     * @param userId The Id of the user to enable Two Factor authentication.
     * @param request The two factor enable request information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> EnableTwoFactor(Guid? userId, TwoFactorRequest request) {
      return buildClient()
          .withUri("/api/user/two-factor")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Exchange a refresh token for a new JWT.
     *
     * @param request The refresh request.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RefreshResponse> ExchangeRefreshTokenForJWT(RefreshRequest request) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withJSONBody(request)
          .withMethod("Post")
          .go<RefreshResponse>();
    }
    /**
     * Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
     *
     * @param request The request that contains the information about the user so that they can be emailed.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ForgotPasswordResponse> ForgotPassword(ForgotPasswordRequest request) {
      return buildClient()
          .withUri("/api/user/forgot-password")
          .withJSONBody(request)
          .withMethod("Post")
          .go<ForgotPasswordResponse>();
    }
    /**
     * Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
     * email to the User. This API may be used to collect the verificationId for use with a third party system.
     *
     * @param email The email address of the user that needs a new verification email.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<VerifyEmailResponse> GenerateEmailVerificationId(string email) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withParameter("email", email)
          .withParameter("sendVerifyEmail", false)
          .withMethod("Put")
          .go<VerifyEmailResponse>();
    }
    /**
     * Generate a new RSA or EC key pair or an HMAC secret.
     *
     * @param keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the key.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<KeyResponse> GenerateKey(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key/generate")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<KeyResponse>();
    }
    /**
     * Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
     * email to the User. This API may be used to collect the verificationId for use with a third party system.
     *
     * @param email The email address of the user that needs a new verification email.
     * @param applicationId The Id of the application to be verified.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<VerifyRegistrationResponse> GenerateRegistrationVerificationId(string email, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/verify-registration")
          .withParameter("email", email)
          .withParameter("sendVerifyPasswordEmail", false)
          .withParameter("applicationId", applicationId)
          .withMethod("Put")
          .go<VerifyRegistrationResponse>();
    }
    /**
     * Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
     * both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
     * application such as Google Authenticator.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<SecretResponse> GenerateTwoFactorSecret() {
      return buildClient()
          .withUri("/api/two-factor/secret")
          .withMethod("Get")
          .go<SecretResponse>();
    }
    /**
     * Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
     * both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
     * application such as Google Authenticator.
     *
     * @param encodedJWT The encoded JWT (access token).
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<SecretResponse> GenerateTwoFactorSecretUsingJWT(string encodedJWT) {
      return buildClient()
          .withUri("/api/two-factor/secret")
          .withAuthorization("JWT " + encodedJWT)
          .withMethod("Get")
          .go<SecretResponse>();
    }
    /**
     * Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
     * login systems.
     *
     * @param request The third-party login request that contains information from the third-party login
     * providers that FusionAuth uses to reconcile the user's account.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginResponse> IdentityProviderLogin(IdentityProviderLoginRequest request) {
      return buildClient()
          .withUri("/api/identity-provider/login")
          .withJSONBody(request)
          .withMethod("Post")
          .go<LoginResponse>();
    }
    /**
     * Import an existing RSA or EC key pair or an HMAC secret.
     *
     * @param keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
     * @param request The request object that contains all of the information used to create the key.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<KeyResponse> ImportKey(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key/import")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<KeyResponse>();
    }
    /**
     * Bulk imports multiple users. This does some validation, but then tries to run batch inserts of users. This reduces
     * latency when inserting lots of users. Therefore, the error response might contain some information about failures,
     * but it will likely be pretty generic.
     *
     * @param request The request that contains all of the information about all of the users to import.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> ImportUsers(ImportRequest request) {
      return buildClient()
          .withUri("/api/user/import")
          .withJSONBody(request)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
     * access token is properly signed and not expired.
     * <p>
     * This API may be used in an SSO configuration to issue new tokens for another application after the user has
     * obtained a valid token from authentication.
     *
     * @param applicationId The Application Id for which you are requesting a new access token be issued.
     * @param encodedJWT The encoded JWT (access token).
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<IssueResponse> IssueJWT(Guid? applicationId, string encodedJWT) {
      return buildClient()
          .withUri("/api/jwt/issue")
          .withAuthorization("JWT " + encodedJWT)
          .withParameter("applicationId", applicationId)
          .withMethod("Get")
          .go<IssueResponse>();
    }
    /**
     * Authenticates a user to FusionAuth. 
     * 
     * This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
     *
     * @param request The login request that contains the user credentials used to log them in.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginResponse> Login(LoginRequest request) {
      return buildClient()
          .withUri("/api/login")
          .withJSONBody(request)
          .withMethod("Post")
          .go<LoginResponse>();
    }
    /**
     * Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
     * FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
     * application where they no longer have a session. This helps correctly track login counts, times and helps with
     * reporting.
     *
     * @param userId The Id of the user that was logged in.
     * @param applicationId The Id of the application that they logged into.
     * @param callerIPAddress (Optional) The IP address of the end-user that is logging in. If a null value is provided
     * the IP address will be that of the client or last proxy that sent the request.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> LoginPing(Guid? userId, Guid? applicationId, string callerIPAddress) {
      return buildClient()
          .withUri("/api/login")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withParameter("ipAddress", callerIPAddress)
          .withMethod("Put")
          .go<RESTVoid>();
    }
    /**
     * The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
     * client and revoke the refresh token stored. This API does nothing if the request does not contain an access
     * token or refresh token cookies.
     *
     * @param global When this value is set to true all of the refresh tokens issued to the owner of the
     * provided token will be revoked.
     * @param refreshToken (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
     * If provided this takes precedence over the cookie.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> Logout(bool? global, string refreshToken) {
      return buildClient()
          .withUri("/api/logout")
          .withParameter("global", global)
          .withParameter("refreshToken", refreshToken)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
     * by a registered identity provider. A 404 indicates the domain is not managed.
     *
     * @param domain The domain or email address to lookup.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LookupResponse> LookupIdentityProvider(string domain) {
      return buildClient()
          .withUri("/api/identity-provider/lookup")
          .withParameter("domain", domain)
          .withMethod("Get")
          .go<LookupResponse>();
    }
    /**
     * Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
     * action.
     *
     * @param actionId The Id of the action to modify. This is technically the user action log id.
     * @param request The request that contains all of the information about the modification.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ActionResponse> ModifyAction(Guid? actionId, ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<ActionResponse>();
    }
    /**
     * Complete a login request using a passwordless code
     *
     * @param request The passwordless login request that contains all of the information used to complete login.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginResponse> PasswordlessLogin(PasswordlessLoginRequest request) {
      return buildClient()
          .withUri("/api/passwordless/login")
          .withJSONBody(request)
          .withMethod("Post")
          .go<LoginResponse>();
    }
    /**
     * Reactivates the application with the given Id.
     *
     * @param applicationId The Id of the application to reactivate.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ApplicationResponse> ReactivateApplication(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .go<ApplicationResponse>();
    }
    /**
     * Reactivates the user with the given Id.
     *
     * @param userId The Id of the user to reactivate.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> ReactivateUser(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .go<UserResponse>();
    }
    /**
     * Reactivates the user action with the given Id.
     *
     * @param userActionId The Id of the user action to reactivate.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionResponse> ReactivateUserAction(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .go<UserActionResponse>();
    }
    /**
     * Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
     *
     * @param request The reconcile request that contains the data to reconcile the User.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginResponse> ReconcileJWT(IdentityProviderLoginRequest request) {
      return buildClient()
          .withUri("/api/jwt/reconcile")
          .withJSONBody(request)
          .withMethod("Post")
          .go<LoginResponse>();
    }
    /**
     * Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
     * reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
     * if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
     *  ensure the index immediately current before making a query request to the search index.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> RefreshUserSearchIndex() {
      return buildClient()
          .withUri("/api/user/search")
          .withMethod("Put")
          .go<RESTVoid>();
    }
    /**
     * Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
     * will create the user as well as register them for the application. This is called a Full Registration. However, if
     * you only provide the UserRegistration object, then the user must already exist and they will be registered for the
     * application. The user id can also be provided and it will either be used to look up an existing user or it will be
     * used for the newly created User.
     *
     * @param userId (Optional) The Id of the user being registered for the application and optionally created.
     * @param request The request that optionally contains the User and must contain the UserRegistration.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RegistrationResponse> Register(Guid? userId, RegistrationRequest request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<RegistrationResponse>();
    }
    /**
     * Removes a user from the family with the given id.
     *
     * @param familyId The id of the family to remove the user from.
     * @param userId The id of the user to remove from the family.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> RemoveUserFromFamily(Guid? familyId, Guid? userId) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withUriSegment(userId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Re-sends the verification email to the user.
     *
     * @param email The email address of the user that needs a new verification email.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<VerifyEmailResponse> ResendEmailVerification(string email) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withParameter("email", email)
          .withMethod("Put")
          .go<VerifyEmailResponse>();
    }
    /**
     * Re-sends the application registration verification email to the user.
     *
     * @param email The email address of the user that needs a new verification email.
     * @param applicationId The Id of the application to be verified.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<VerifyRegistrationResponse> ResendRegistrationVerification(string email, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/verify-registration")
          .withParameter("email", email)
          .withParameter("applicationId", applicationId)
          .withMethod("Put")
          .go<VerifyRegistrationResponse>();
    }
    /**
     * Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
     *
     * @param actionId The Id of the action to retrieve.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ActionResponse> RetrieveAction(Guid? actionId) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withMethod("Get")
          .go<ActionResponse>();
    }
    /**
     * Retrieves all of the actions for the user with the given Id. This will return all time based actions that are active,
     * and inactive as well as non-time based actions.
     *
     * @param userId The Id of the user to fetch the actions for.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ActionResponse> RetrieveActions(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withMethod("Get")
          .go<ActionResponse>();
    }
    /**
     * Retrieves all of the actions for the user with the given Id that are currently preventing the User from logging in.
     *
     * @param userId The Id of the user to fetch the actions for.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ActionResponse> RetrieveActionsPreventingLogin(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("preventingLogin", true)
          .withMethod("Get")
          .go<ActionResponse>();
    }
    /**
     * Retrieves all of the actions for the user with the given Id that are currently active.
     * An active action means one that is time based and has not been canceled, and has not ended.
     *
     * @param userId The Id of the user to fetch the actions for.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ActionResponse> RetrieveActiveActions(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("active", true)
          .withMethod("Get")
          .go<ActionResponse>();
    }
    /**
     * Retrieves the application for the given id or all of the applications if the id is null.
     *
     * @param applicationId (Optional) The application id.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ApplicationResponse> RetrieveApplication(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withMethod("Get")
          .go<ApplicationResponse>();
    }
    /**
     * Retrieves all of the applications.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ApplicationResponse> RetrieveApplications() {
      return buildClient()
          .withUri("/api/application")
          .withMethod("Get")
          .go<ApplicationResponse>();
    }
    /**
     * Retrieves a single audit log for the given Id.
     *
     * @param auditLogId The Id of the audit log to retrieve.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<AuditLogResponse> RetrieveAuditLog(int? auditLogId) {
      return buildClient()
          .withUri("/api/system/audit-log")
          .withUriSegment(auditLogId)
          .withMethod("Get")
          .go<AuditLogResponse>();
    }
    /**
     * Retrieves the Consent for the given Id.
     *
     * @param consentId The Id of the consent.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ConsentResponse> RetrieveConsent(Guid? consentId) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withMethod("Get")
          .go<ConsentResponse>();
    }
    /**
     * Retrieves all of the consent.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ConsentResponse> RetrieveConsents() {
      return buildClient()
          .withUri("/api/consent")
          .withMethod("Get")
          .go<ConsentResponse>();
    }
    /**
     * Retrieves the daily active user report between the two instants. If you specify an application id, it will only
     * return the daily active counts for that application.
     *
     * @param applicationId (Optional) The application id.
     * @param start The start instant as UTC milliseconds since Epoch.
     * @param end The end instant as UTC milliseconds since Epoch.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<DailyActiveUserReportResponse> RetrieveDailyActiveReport(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/daily-active-user")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .go<DailyActiveUserReportResponse>();
    }
    /**
     * Retrieves the email template for the given Id. If you don't specify the id, this will return all of the email templates.
     *
     * @param emailTemplateId (Optional) The Id of the email template.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<EmailTemplateResponse> RetrieveEmailTemplate(Guid? emailTemplateId) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withMethod("Get")
          .go<EmailTemplateResponse>();
    }
    /**
     * Creates a preview of the email template provided in the request. This allows you to preview an email template that
     * hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
     * will create the preview based on whatever is given.
     *
     * @param request The request that contains the email template and optionally a locale to render it in.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<PreviewResponse> RetrieveEmailTemplatePreview(PreviewRequest request) {
      return buildClient()
          .withUri("/api/email/template/preview")
          .withJSONBody(request)
          .withMethod("Post")
          .go<PreviewResponse>();
    }
    /**
     * Retrieves all of the email templates.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<EmailTemplateResponse> RetrieveEmailTemplates() {
      return buildClient()
          .withUri("/api/email/template")
          .withMethod("Get")
          .go<EmailTemplateResponse>();
    }
    /**
     * Retrieves a single event log for the given Id.
     *
     * @param eventLogId The Id of the event log to retrieve.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<EventLogResponse> RetrieveEventLog(int? eventLogId) {
      return buildClient()
          .withUri("/api/system/event-log")
          .withUriSegment(eventLogId)
          .withMethod("Get")
          .go<EventLogResponse>();
    }
    /**
     * Retrieves all of the families that a user belongs to.
     *
     * @param userId The User's id
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<FamilyResponse> RetrieveFamilies(Guid? userId) {
      return buildClient()
          .withUri("/api/user/family")
          .withParameter("userId", userId)
          .withMethod("Get")
          .go<FamilyResponse>();
    }
    /**
     * Retrieves all of the members of a family by the unique Family Id.
     *
     * @param familyId The unique Id of the Family.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<FamilyResponse> RetrieveFamilyMembersByFamilyId(Guid? familyId) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withMethod("Get")
          .go<FamilyResponse>();
    }
    /**
     * Retrieves the group for the given Id.
     *
     * @param groupId The Id of the group.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<GroupResponse> RetrieveGroup(Guid? groupId) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withMethod("Get")
          .go<GroupResponse>();
    }
    /**
     * Retrieves all of the groups.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<GroupResponse> RetrieveGroups() {
      return buildClient()
          .withUri("/api/group")
          .withMethod("Get")
          .go<GroupResponse>();
    }
    /**
     * Retrieves the identity provider for the given id or all of the identity providers if the id is null.
     *
     * @param identityProviderId (Optional) The identity provider id.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<IdentityProviderResponse> RetrieveIdentityProvider(Guid? identityProviderId) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withMethod("Get")
          .go<IdentityProviderResponse>();
    }
    /**
     * Retrieves all of the identity providers.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<IdentityProviderResponse> RetrieveIdentityProviders() {
      return buildClient()
          .withUri("/api/identity-provider")
          .withMethod("Get")
          .go<IdentityProviderResponse>();
    }
    /**
     * Retrieves all of the actions for the user with the given Id that are currently inactive.
     * An inactive action means one that is time based and has been canceled or has expired, or is not time based.
     *
     * @param userId The Id of the user to fetch the actions for.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ActionResponse> RetrieveInactiveActions(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("active", false)
          .withMethod("Get")
          .go<ActionResponse>();
    }
    /**
     * Retrieves all of the applications that are currently inactive.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ApplicationResponse> RetrieveInactiveApplications() {
      return buildClient()
          .withUri("/api/application")
          .withParameter("inactive", true)
          .withMethod("Get")
          .go<ApplicationResponse>();
    }
    /**
     * Retrieves all of the user actions that are currently inactive.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionResponse> RetrieveInactiveUserActions() {
      return buildClient()
          .withUri("/api/user-action")
          .withParameter("inactive", true)
          .withMethod("Get")
          .go<UserActionResponse>();
    }
    /**
     * Retrieves the available integrations.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<IntegrationResponse> RetrieveIntegration() {
      return buildClient()
          .withUri("/api/integration")
          .withMethod("Get")
          .go<IntegrationResponse>();
    }
    /**
     * Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
     *
     * @param keyId The Id of the public key (kid).
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKey(string keyId) {
      return buildClient()
          .withUri("/api/jwt/public-key")
          .withParameter("kid", keyId)
          .withMethod("Get")
          .go<PublicKeyResponse>();
    }
    /**
     * Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
     *
     * @param applicationId The Id of the Application for which this key is used.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKeyByApplicationId(string applicationId) {
      return buildClient()
          .withUri("/api/jwt/public-key")
          .withParameter("applicationId", applicationId)
          .withMethod("Get")
          .go<PublicKeyResponse>();
    }
    /**
     * Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKeys() {
      return buildClient()
          .withUri("/api/jwt/public-key")
          .withMethod("Get")
          .go<PublicKeyResponse>();
    }
    /**
     * Retrieves the key for the given Id.
     *
     * @param keyId The Id of the key.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<KeyResponse> RetrieveKey(Guid? keyId) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyId)
          .withMethod("Get")
          .go<KeyResponse>();
    }
    /**
     * Retrieves all of the keys.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<KeyResponse> RetrieveKeys() {
      return buildClient()
          .withUri("/api/key")
          .withMethod("Get")
          .go<KeyResponse>();
    }
    /**
     * Retrieves the lambda for the given Id.
     *
     * @param lambdaId The Id of the lambda.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LambdaResponse> RetrieveLambda(Guid? lambdaId) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withMethod("Get")
          .go<LambdaResponse>();
    }
    /**
     * Retrieves all of the lambdas.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LambdaResponse> RetrieveLambdas() {
      return buildClient()
          .withUri("/api/lambda")
          .withMethod("Get")
          .go<LambdaResponse>();
    }
    /**
     * Retrieves all of the lambdas for the provided type.
     *
     * @param type The type of the lambda to return.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LambdaResponse> RetrieveLambdasByType(LambdaType type) {
      return buildClient()
          .withUri("/api/lambda")
          .withParameter("type", type)
          .withMethod("Get")
          .go<LambdaResponse>();
    }
    /**
     * Retrieves the login report between the two instants. If you specify an application id, it will only return the
     * login counts for that application.
     *
     * @param applicationId (Optional) The application id.
     * @param start The start instant as UTC milliseconds since Epoch.
     * @param end The end instant as UTC milliseconds since Epoch.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginReportResponse> RetrieveLoginReport(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/login")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .go<LoginReportResponse>();
    }
    /**
     * Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
     * return the monthly active counts for that application.
     *
     * @param applicationId (Optional) The application id.
     * @param start The start instant as UTC milliseconds since Epoch.
     * @param end The end instant as UTC milliseconds since Epoch.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<MonthlyActiveUserReportResponse> RetrieveMonthlyActiveReport(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/monthly-active-user")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .go<MonthlyActiveUserReportResponse>();
    }
    /**
     * Retrieves the Oauth2 configuration for the application for the given Application Id.
     *
     * @param applicationId The Id of the Application to retrieve OAuth configuration.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<OAuthConfigurationResponse> RetrieveOauthConfiguration(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("oauth-configuration")
          .withMethod("Get")
          .go<OAuthConfigurationResponse>();
    }
    /**
     * Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided 
     * through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
     * 
     * This API does not require an API key.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<PasswordValidationRulesResponse> RetrievePasswordValidationRules() {
      return buildClient()
          .withUri("/api/tenant/password-validation-rules")
          .withMethod("Get")
          .go<PasswordValidationRulesResponse>();
    }
    /**
     * Retrieves the password validation rules for a specific tenant.
     * 
     * This API does not require an API key.
     *
     * @param tenantId The Id of the tenant.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<PasswordValidationRulesResponse> RetrievePasswordValidationRulesWithTenantId(Guid? tenantId) {
      return buildClient()
          .withUri("/api/tenant/password-validation-rules")
          .withUriSegment(tenantId)
          .withMethod("Get")
          .go<PasswordValidationRulesResponse>();
    }
    /**
     * Retrieves all of the children for the given parent email address.
     *
     * @param parentEmail The email of the parent.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<PendingResponse> RetrievePendingChildren(string parentEmail) {
      return buildClient()
          .withUri("/api/user/family/pending")
          .withParameter("parentEmail", parentEmail)
          .withMethod("Get")
          .go<PendingResponse>();
    }
    /**
     * Retrieves the last number of login records.
     *
     * @param offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
     * @param limit (Optional, defaults to 10) The number of records to retrieve.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RecentLoginResponse> RetrieveRecentLogins(int? offset, int? limit) {
      return buildClient()
          .withUri("/api/user/recent-login")
          .withParameter("offset", offset)
          .withParameter("limit", limit)
          .withMethod("Get")
          .go<RecentLoginResponse>();
    }
    /**
     * Retrieves the refresh tokens that belong to the user with the given Id.
     *
     * @param userId The Id of the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RefreshResponse> RetrieveRefreshTokens(Guid? userId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("userId", userId)
          .withMethod("Get")
          .go<RefreshResponse>();
    }
    /**
     * Retrieves the user registration for the user with the given id and the given application id.
     *
     * @param userId The Id of the user.
     * @param applicationId The Id of the application.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RegistrationResponse> RetrieveRegistration(Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withMethod("Get")
          .go<RegistrationResponse>();
    }
    /**
     * Retrieves the registration report between the two instants. If you specify an application id, it will only return
     * the registration counts for that application.
     *
     * @param applicationId (Optional) The application id.
     * @param start The start instant as UTC milliseconds since Epoch.
     * @param end The end instant as UTC milliseconds since Epoch.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RegistrationReportResponse> RetrieveRegistrationReport(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/registration")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .go<RegistrationReportResponse>();
    }
    /**
     * Retrieves the system configuration.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<SystemConfigurationResponse> RetrieveSystemConfiguration() {
      return buildClient()
          .withUri("/api/system-configuration")
          .withMethod("Get")
          .go<SystemConfigurationResponse>();
    }
    /**
     * Retrieves the tenant for the given Id.
     *
     * @param tenantId The Id of the tenant.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<TenantResponse> RetrieveTenant(Guid? tenantId) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withMethod("Get")
          .go<TenantResponse>();
    }
    /**
     * Retrieves all of the tenants.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<TenantResponse> RetrieveTenants() {
      return buildClient()
          .withUri("/api/tenant")
          .withMethod("Get")
          .go<TenantResponse>();
    }
    /**
     * Retrieves the theme for the given Id.
     *
     * @param themeId The Id of the theme.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ThemeResponse> RetrieveTheme(Guid? themeId) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withMethod("Get")
          .go<ThemeResponse>();
    }
    /**
     * Retrieves all of the themes.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ThemeResponse> RetrieveThemes() {
      return buildClient()
          .withUri("/api/theme")
          .withMethod("Get")
          .go<ThemeResponse>();
    }
    /**
     * Retrieves the totals report. This contains all of the total counts for each application and the global registration
     * count.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<TotalsReportResponse> RetrieveTotalReport() {
      return buildClient()
          .withUri("/api/report/totals")
          .withMethod("Get")
          .go<TotalsReportResponse>();
    }
    /**
     * Retrieves the user for the given Id.
     *
     * @param userId The Id of the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> RetrieveUser(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withMethod("Get")
          .go<UserResponse>();
    }
    /**
     * Retrieves the user action for the given Id. If you pass in null for the id, this will return all of the user
     * actions.
     *
     * @param userActionId (Optional) The Id of the user action.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionResponse> RetrieveUserAction(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withMethod("Get")
          .go<UserActionResponse>();
    }
    /**
     * Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all of the user
     * action reasons.
     *
     * @param userActionReasonId (Optional) The Id of the user action reason.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionReasonResponse> RetrieveUserActionReason(Guid? userActionReasonId) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withMethod("Get")
          .go<UserActionReasonResponse>();
    }
    /**
     * Retrieves all the user action reasons.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionReasonResponse> RetrieveUserActionReasons() {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withMethod("Get")
          .go<UserActionReasonResponse>();
    }
    /**
     * Retrieves all of the user actions.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionResponse> RetrieveUserActions() {
      return buildClient()
          .withUri("/api/user-action")
          .withMethod("Get")
          .go<UserActionResponse>();
    }
    /**
     * Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
     * password workflow has been initiated and you may not know the user's email or username.
     *
     * @param changePasswordId The unique change password Id that was sent via email or returned by the Forgot Password API.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> RetrieveUserByChangePasswordId(string changePasswordId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("changePasswordId", changePasswordId)
          .withMethod("Get")
          .go<UserResponse>();
    }
    /**
     * Retrieves the user for the given email.
     *
     * @param email The email of the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> RetrieveUserByEmail(string email) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("email", email)
          .withMethod("Get")
          .go<UserResponse>();
    }
    /**
     * Retrieves the user for the loginId. The loginId can be either the username or the email.
     *
     * @param loginId The email or username of the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> RetrieveUserByLoginId(string loginId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("loginId", loginId)
          .withMethod("Get")
          .go<UserResponse>();
    }
    /**
     * Retrieves the user for the given username.
     *
     * @param username The username of the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> RetrieveUserByUsername(string username) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("username", username)
          .withMethod("Get")
          .go<UserResponse>();
    }
    /**
     * Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
     * password workflow has been initiated and you may not know the user's email or username.
     *
     * @param verificationId The unique verification Id that has been set on the user object.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> RetrieveUserByVerificationId(string verificationId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("verificationId", verificationId)
          .withMethod("Get")
          .go<UserResponse>();
    }
    /**
     * Retrieves all of the comments for the user with the given Id.
     *
     * @param userId The Id of the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserCommentResponse> RetrieveUserComments(Guid? userId) {
      return buildClient()
          .withUri("/api/user/comment")
          .withUriSegment(userId)
          .withMethod("Get")
          .go<UserCommentResponse>();
    }
    /**
     * Retrieve a single User consent by Id.
     *
     * @param userConsentId The User consent Id
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserConsentResponse> RetrieveUserConsent(Guid? userConsentId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withMethod("Get")
          .go<UserConsentResponse>();
    }
    /**
     * Retrieves all of the consents for a User.
     *
     * @param userId The User's Id
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserConsentResponse> RetrieveUserConsents(Guid? userId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withParameter("userId", userId)
          .withMethod("Get")
          .go<UserConsentResponse>();
    }
    /**
     * Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
     * login counts for that application.
     *
     * @param applicationId (Optional) The application id.
     * @param userId The userId id.
     * @param start The start instant as UTC milliseconds since Epoch.
     * @param end The end instant as UTC milliseconds since Epoch.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginReportResponse> RetrieveUserLoginReport(Guid? applicationId, Guid? userId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/login")
          .withParameter("applicationId", applicationId)
          .withParameter("userId", userId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .go<LoginReportResponse>();
    }
    /**
     * Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
     * login counts for that application.
     *
     * @param applicationId (Optional) The application id.
     * @param loginId The userId id.
     * @param start The start instant as UTC milliseconds since Epoch.
     * @param end The end instant as UTC milliseconds since Epoch.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginReportResponse> RetrieveUserLoginReportByLoginId(Guid? applicationId, string loginId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/login")
          .withParameter("applicationId", applicationId)
          .withParameter("loginId", loginId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .go<LoginReportResponse>();
    }
    /**
     * Retrieves the last number of login records for a user.
     *
     * @param userId The Id of the user.
     * @param offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
     * @param limit (Optional, defaults to 10) The number of records to retrieve.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RecentLoginResponse> RetrieveUserRecentLogins(Guid? userId, int? offset, int? limit) {
      return buildClient()
          .withUri("/api/user/recent-login")
          .withParameter("userId", userId)
          .withParameter("offset", offset)
          .withParameter("limit", limit)
          .withMethod("Get")
          .go<RecentLoginResponse>();
    }
    /**
     * Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
     *
     * @param encodedJWT The encoded JWT (access token).
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> RetrieveUserUsingJWT(string encodedJWT) {
      return buildClient()
          .withUri("/api/user")
          .withAuthorization("JWT " + encodedJWT)
          .withMethod("Get")
          .go<UserResponse>();
    }
    /**
     * Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
     *
     * @param webhookId (Optional) The Id of the webhook.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<WebhookResponse> RetrieveWebhook(Guid? webhookId) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withMethod("Get")
          .go<WebhookResponse>();
    }
    /**
     * Retrieves all the webhooks.
     *
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<WebhookResponse> RetrieveWebhooks() {
      return buildClient()
          .withUri("/api/webhook")
          .withMethod("Get")
          .go<WebhookResponse>();
    }
    /**
     * Revokes a single refresh token, all tokens for a user or all tokens for an application. If you provide a user id
     * and an application id, this will delete all the refresh tokens for that user for that application.
     *
     * @param token (Optional) The refresh token to delete.
     * @param userId (Optional) The user id whose tokens to delete.
     * @param applicationId (Optional) The application id of the tokens to delete.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> RevokeRefreshToken(string token, Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("token", token)
          .withParameter("userId", userId)
          .withParameter("applicationId", applicationId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Revokes a single User consent by Id.
     *
     * @param userConsentId The User Consent Id
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> RevokeUserConsent(Guid? userConsentId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withMethod("Delete")
          .go<RESTVoid>();
    }
    /**
     * Searches the audit logs with the specified criteria and pagination.
     *
     * @param request The search criteria and pagination information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<AuditLogSearchResponse> SearchAuditLogs(AuditLogSearchRequest request) {
      return buildClient()
          .withUri("/api/system/audit-log/search")
          .withJSONBody(request)
          .withMethod("Post")
          .go<AuditLogSearchResponse>();
    }
    /**
     * Searches the event logs with the specified criteria and pagination.
     *
     * @param request The search criteria and pagination information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<EventLogSearchResponse> SearchEventLogs(EventLogSearchRequest request) {
      return buildClient()
          .withUri("/api/system/event-log/search")
          .withJSONBody(request)
          .withMethod("Post")
          .go<EventLogSearchResponse>();
    }
    /**
     * Searches the login records with the specified criteria and pagination.
     *
     * @param request The search criteria and pagination information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginRecordSearchResponse> SearchLoginRecords(LoginRecordSearchRequest request) {
      return buildClient()
          .withUri("/api/system/login-record/search")
          .withJSONBody(request)
          .withMethod("Post")
          .go<LoginRecordSearchResponse>();
    }
    /**
     * Retrieves the users for the given ids. If any id is invalid, it is ignored.
     *
     * @param ids The user ids to search for.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<SearchResponse> SearchUsers(List<string> ids) {
      return buildClient()
          .withUri("/api/user/search")
          .withParameter("ids", ids)
          .withMethod("Get")
          .go<SearchResponse>();
    }
    /**
     * Retrieves the users for the given search criteria and pagination.
     *
     * @param request The search criteria and pagination constraints. Fields used: queryString, numberOfResults, startRow,
     * and sort fields.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<SearchResponse> SearchUsersByQueryString(SearchRequest request) {
      return buildClient()
          .withUri("/api/user/search")
          .withJSONBody(request)
          .withMethod("Post")
          .go<SearchResponse>();
    }
    /**
     * Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
     * pairs in the email template.
     *
     * @param emailTemplateId The id for the template.
     * @param request The send email request that contains all of the information used to send the email.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<SendResponse> SendEmail(Guid? emailTemplateId, SendRequest request) {
      return buildClient()
          .withUri("/api/email/send")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Post")
          .go<SendResponse>();
    }
    /**
     * Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
     *
     * @param request The request object that contains the parent email.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> SendFamilyRequestEmail(FamilyEmailRequest request) {
      return buildClient()
          .withUri("/api/user/family/request")
          .withJSONBody(request)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Send a passwordless authentication code in an email to complete login.
     *
     * @param request The passwordless send request that contains all of the information used to send an email containing a code.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> SendPasswordlessCode(PasswordlessSendRequest request) {
      return buildClient()
          .withUri("/api/passwordless/send")
          .withJSONBody(request)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
     *
     * @param request The request object that contains all of the information used to send the code.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> SendTwoFactorCode(TwoFactorSendRequest request) {
      return buildClient()
          .withUri("/api/two-factor/send")
          .withJSONBody(request)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Send a Two Factor authentication code to allow the completion of Two Factor authentication.
     *
     * @param twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> SendTwoFactorCodeForLogin(string twoFactorId) {
      return buildClient()
          .withUri("/api/two-factor/send")
          .withUriSegment(twoFactorId)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Complete login using a 2FA challenge
     *
     * @param request The login request that contains the user credentials used to log them in.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LoginResponse> TwoFactorLogin(TwoFactorLoginRequest request) {
      return buildClient()
          .withUri("/api/two-factor/login")
          .withJSONBody(request)
          .withMethod("Post")
          .go<LoginResponse>();
    }
    /**
     * Updates the application with the given Id.
     *
     * @param applicationId The Id of the application to update.
     * @param request The request that contains all of the new application information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ApplicationResponse> UpdateApplication(Guid? applicationId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<ApplicationResponse>();
    }
    /**
     * Updates the application role with the given id for the application.
     *
     * @param applicationId The Id of the application that the role belongs to.
     * @param roleId The Id of the role to update.
     * @param request The request that contains all of the new role information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ApplicationResponse> UpdateApplicationRole(Guid? applicationId, Guid? roleId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<ApplicationResponse>();
    }
    /**
     * Updates the consent with the given Id.
     *
     * @param consentId The Id of the consent to update.
     * @param request The request that contains all of the new consent information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ConsentResponse> UpdateConsent(Guid? consentId, ConsentRequest request) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<ConsentResponse>();
    }
    /**
     * Updates the email template with the given Id.
     *
     * @param emailTemplateId The Id of the email template to update.
     * @param request The request that contains all of the new email template information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<EmailTemplateResponse> UpdateEmailTemplate(Guid? emailTemplateId, EmailTemplateRequest request) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<EmailTemplateResponse>();
    }
    /**
     * Updates the group with the given Id.
     *
     * @param groupId The Id of the group to update.
     * @param request The request that contains all of the new group information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<GroupResponse> UpdateGroup(Guid? groupId, GroupRequest request) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<GroupResponse>();
    }
    /**
     * Updates the identity provider with the given Id.
     *
     * @param identityProviderId The Id of the identity provider to update.
     * @param request The request object that contains the updated identity provider.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<IdentityProviderResponse> UpdateIdentityProvider(Guid? identityProviderId, IdentityProviderRequest request) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<IdentityProviderResponse>();
    }
    /**
     * Updates the available integrations.
     *
     * @param request The request that contains all of the new integration information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<IntegrationResponse> UpdateIntegrations(IntegrationRequest request) {
      return buildClient()
          .withUri("/api/integration")
          .withJSONBody(request)
          .withMethod("Put")
          .go<IntegrationResponse>();
    }
    /**
     * Updates the key with the given Id.
     *
     * @param keyId The Id of the key to update.
     * @param request The request that contains all of the new key information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<KeyResponse> UpdateKey(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<KeyResponse>();
    }
    /**
     * Updates the lambda with the given Id.
     *
     * @param lambdaId The Id of the lambda to update.
     * @param request The request that contains all of the new lambda information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<LambdaResponse> UpdateLambda(Guid? lambdaId, LambdaRequest request) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<LambdaResponse>();
    }
    /**
     * Updates the registration for the user with the given id and the application defined in the request.
     *
     * @param userId The Id of the user whose registration is going to be updated.
     * @param request The request that contains all of the new registration information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RegistrationResponse> UpdateRegistration(Guid? userId, RegistrationRequest request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<RegistrationResponse>();
    }
    /**
     * Updates the system configuration.
     *
     * @param request The request that contains all of the new system configuration information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<SystemConfigurationResponse> UpdateSystemConfiguration(SystemConfigurationRequest request) {
      return buildClient()
          .withUri("/api/system-configuration")
          .withJSONBody(request)
          .withMethod("Put")
          .go<SystemConfigurationResponse>();
    }
    /**
     * Updates the tenant with the given Id.
     *
     * @param tenantId The Id of the tenant to update.
     * @param request The request that contains all of the new tenant information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<TenantResponse> UpdateTenant(Guid? tenantId, TenantRequest request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<TenantResponse>();
    }
    /**
     * Updates the theme with the given Id.
     *
     * @param themeId The Id of the theme to update.
     * @param request The request that contains all of the new theme information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ThemeResponse> UpdateTheme(Guid? themeId, ThemeRequest request) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<ThemeResponse>();
    }
    /**
     * Updates the user with the given Id.
     *
     * @param userId The Id of the user to update.
     * @param request The request that contains all of the new user information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserResponse> UpdateUser(Guid? userId, UserRequest request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<UserResponse>();
    }
    /**
     * Updates the user action with the given Id.
     *
     * @param userActionId The Id of the user action to update.
     * @param request The request that contains all of the new user action information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionResponse> UpdateUserAction(Guid? userActionId, UserActionRequest request) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<UserActionResponse>();
    }
    /**
     * Updates the user action reason with the given Id.
     *
     * @param userActionReasonId The Id of the user action reason to update.
     * @param request The request that contains all of the new user action reason information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserActionReasonResponse> UpdateUserActionReason(Guid? userActionReasonId, UserActionReasonRequest request) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<UserActionReasonResponse>();
    }
    /**
     * Updates a single User consent by Id.
     *
     * @param userConsentId The User Consent Id
     * @param request The request that contains the user consent information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<UserConsentResponse> UpdateUserConsent(Guid? userConsentId, UserConsentRequest request) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<UserConsentResponse>();
    }
    /**
     * Updates the webhook with the given Id.
     *
     * @param webhookId The Id of the webhook to update.
     * @param request The request that contains all of the new webhook information.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<WebhookResponse> UpdateWebhook(Guid? webhookId, WebhookRequest request) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withJSONBody(request)
          .withMethod("Put")
          .go<WebhookResponse>();
    }
    /**
     * Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
     * signed and not expired.
     * <p>
     * This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
     *
     * @param encodedJWT The encoded JWT (access token).
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<ValidateResponse> ValidateJWT(string encodedJWT) {
      return buildClient()
          .withUri("/api/jwt/validate")
          .withAuthorization("JWT " + encodedJWT)
          .withMethod("Get")
          .go<ValidateResponse>();
    }
    /**
     * Confirms a email verification. The Id given is usually from an email sent to the user.
     *
     * @param verificationId The email verification id sent to the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> VerifyEmail(string verificationId) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withUriSegment(verificationId)
          .withMethod("Post")
          .go<RESTVoid>();
    }
    /**
     * Confirms an application registration. The Id given is usually from an email sent to the user.
     *
     * @param verificationId The registration verification Id sent to the user.
     * @return When successful, the response will contain the log of the action. If there was a validation error or any
     * other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
     * contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
     * IOException.
     */
    public ClientResponse<RESTVoid> VerifyRegistration(string verificationId) {
      return buildClient()
          .withUri("/api/user/verify-registration")
          .withUriSegment(verificationId)
          .withMethod("Post")
          .go<RESTVoid>();
    }

  }

  internal class DefaultRESTClientBuilder : IRESTClientBuilder {
    public IRESTClient build(string host) {
      return new DefaultRESTClient(host);
    }
  }
}
