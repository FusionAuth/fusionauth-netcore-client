/*
 * Copyright (c) 2018-2020, FusionAuth, All Rights Reserved
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

namespace io.fusionauth {
  public class FusionAuthClient {
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

    /// <summary>
    /// Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
    /// "actioner". Both user ids are required in the request object.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The action request that includes all of the information about the action being taken including
    /// the id of the action, any options and the duration (if applicable).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ActionResponse>> ActionUserAsync(ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ActionResponse>();
    }
		
    /// <summary>
    /// Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
    /// "actioner". Both user ids are required in the request object.
    /// </summary>
    /// <param name="request"> The action request that includes all of the information about the action being taken including
     /// the id of the action, any options and the duration (if applicable).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ActionResponse> ActionUser(ActionRequest request) {
      return ActionUserAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Adds a user to an existing family. The family id must be specified.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="familyId"> The id of the family.</param>
    /// <param name="request"> The request object that contains all of the information used to determine which user to add to the family.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<FamilyResponse>> AddUserToFamilyAsync(Guid? familyId, FamilyRequest request) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<FamilyResponse>();
    }
		
    /// <summary>
    /// Adds a user to an existing family. The family id must be specified.
    /// </summary>
    /// <param name="familyId"> The id of the family.</param>
    /// <param name="request"> The request object that contains all of the information used to determine which user to add to the family.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<FamilyResponse> AddUserToFamily(Guid? familyId, FamilyRequest request) {
      return AddUserToFamilyAsync(familyId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Cancels the user action.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="actionId"> The action id of the action to cancel.</param>
    /// <param name="request"> The action request that contains the information about the cancellation.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ActionResponse>> CancelActionAsync(Guid? actionId, ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<ActionResponse>();
    }
		
    /// <summary>
    /// Cancels the user action.
    /// </summary>
    /// <param name="actionId"> The action id of the action to cancel.</param>
    /// <param name="request"> The action request that contains the information about the cancellation.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ActionResponse> CancelAction(Guid? actionId, ActionRequest request) {
      return CancelActionAsync(actionId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
    /// and they clicked on a link to reset their password.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="changePasswordId"> The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.</param>
    /// <param name="request"> The change password request that contains all of the information used to change the password.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ChangePasswordResponse>> ChangePasswordAsync(string changePasswordId, ChangePasswordRequest request) {
      return buildClient()
          .withUri("/api/user/change-password")
          .withUriSegment(changePasswordId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ChangePasswordResponse>();
    }
		
    /// <summary>
    /// Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
    /// and they clicked on a link to reset their password.
    /// </summary>
    /// <param name="changePasswordId"> The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.</param>
    /// <param name="request"> The change password request that contains all of the information used to change the password.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ChangePasswordResponse> ChangePassword(string changePasswordId, ChangePasswordRequest request) {
      return ChangePasswordAsync(changePasswordId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Changes a user's password using their identity (login id and password). Using a loginId instead of the changePasswordId
    /// bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
    /// method.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The change password request that contains all of the information used to change the password.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> ChangePasswordByIdentityAsync(ChangePasswordRequest request) {
      return buildClient()
          .withUri("/api/user/change-password")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Changes a user's password using their identity (login id and password). Using a loginId instead of the changePasswordId
    /// bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
    /// method.
    /// </summary>
    /// <param name="request"> The change password request that contains all of the information used to change the password.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> ChangePasswordByIdentity(ChangePasswordRequest request) {
      return ChangePasswordByIdentityAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Adds a comment to the user's account.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all of the information used to create the user comment.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> CommentOnUserAsync(UserCommentRequest request) {
      return buildClient()
          .withUri("/api/user/comment")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Adds a comment to the user's account.
    /// </summary>
    /// <param name="request"> The request object that contains all of the information used to create the user comment.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> CommentOnUser(UserCommentRequest request) {
      return CommentOnUserAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the application.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ApplicationResponse>> CreateApplicationAsync(Guid? applicationId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ApplicationResponse>();
    }
		
    /// <summary>
    /// Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
    /// </summary>
    /// <param name="applicationId"> (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the application.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> CreateApplication(Guid? applicationId, ApplicationRequest request) {
      return CreateApplicationAsync(applicationId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a new role for an application. You must specify the id of the application you are creating the role for.
    /// You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to create the role on.</param>
    /// <param name="roleId"> (Optional) The Id of the role. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the application role.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
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
		
    /// <summary>
    /// Creates a new role for an application. You must specify the id of the application you are creating the role for.
    /// You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to create the role on.</param>
    /// <param name="roleId"> (Optional) The Id of the role. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the application role.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> CreateApplicationRole(Guid? applicationId, Guid? roleId, ApplicationRequest request) {
      return CreateApplicationRoleAsync(applicationId, roleId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
    /// make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
    /// written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all of the information used to create the audit log entry.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<AuditLogResponse>> CreateAuditLogAsync(AuditLogRequest request) {
      return buildClient()
          .withUri("/api/system/audit-log")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<AuditLogResponse>();
    }
		
    /// <summary>
    /// Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
    /// make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
    /// written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
    /// </summary>
    /// <param name="request"> The request object that contains all of the information used to create the audit log entry.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<AuditLogResponse> CreateAuditLog(AuditLogRequest request) {
      return CreateAuditLogAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> (Optional) The Id for the consent. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the consent.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ConsentResponse>> CreateConsentAsync(Guid? consentId, ConsentRequest request) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ConsentResponse>();
    }
		
    /// <summary>
    /// Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
    /// </summary>
    /// <param name="consentId"> (Optional) The Id for the consent. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the consent.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ConsentResponse> CreateConsent(Guid? consentId, ConsentRequest request) {
      return CreateConsentAsync(consentId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> (Optional) The Id for the template. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the email template.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<EmailTemplateResponse>> CreateEmailTemplateAsync(Guid? emailTemplateId, EmailTemplateRequest request) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EmailTemplateResponse>();
    }
		
    /// <summary>
    /// Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
    /// </summary>
    /// <param name="emailTemplateId"> (Optional) The Id for the template. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the email template.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<EmailTemplateResponse> CreateEmailTemplate(Guid? emailTemplateId, EmailTemplateRequest request) {
      return CreateEmailTemplateAsync(emailTemplateId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a family with the user id in the request as the owner and sole member of the family. You can optionally specify an id for the
    /// family, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="familyId"> (Optional) The id for the family. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the family.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<FamilyResponse>> CreateFamilyAsync(Guid? familyId, FamilyRequest request) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<FamilyResponse>();
    }
		
    /// <summary>
    /// Creates a family with the user id in the request as the owner and sole member of the family. You can optionally specify an id for the
    /// family, if not provided one will be generated.
    /// </summary>
    /// <param name="familyId"> (Optional) The id for the family. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the family.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<FamilyResponse> CreateFamily(Guid? familyId, FamilyRequest request) {
      return CreateFamilyAsync(familyId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> (Optional) The Id for the group. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the group.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<GroupResponse>> CreateGroupAsync(Guid? groupId, GroupRequest request) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<GroupResponse>();
    }
		
    /// <summary>
    /// Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
    /// </summary>
    /// <param name="groupId"> (Optional) The Id for the group. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the group.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<GroupResponse> CreateGroup(Guid? groupId, GroupRequest request) {
      return CreateGroupAsync(groupId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a member in a group.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all of the information used to create the group member(s).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<MemberResponse>> CreateGroupMembersAsync(MemberRequest request) {
      return buildClient()
          .withUri("/api/group/member")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<MemberResponse>();
    }
		
    /// <summary>
    /// Creates a member in a group.
    /// </summary>
    /// <param name="request"> The request object that contains all of the information used to create the group member(s).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<MemberResponse> CreateGroupMembers(MemberRequest request) {
      return CreateGroupMembersAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the identity provider.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IdentityProviderResponse>> CreateIdentityProviderAsync(Guid? identityProviderId, IdentityProviderRequest request) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<IdentityProviderResponse>();
    }
		
    /// <summary>
    /// Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
    /// </summary>
    /// <param name="identityProviderId"> (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the identity provider.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IdentityProviderResponse> CreateIdentityProvider(Guid? identityProviderId, IdentityProviderRequest request) {
      return CreateIdentityProviderAsync(identityProviderId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the lambda.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LambdaResponse>> CreateLambdaAsync(Guid? lambdaId, LambdaRequest request) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LambdaResponse>();
    }
		
    /// <summary>
    /// Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
    /// </summary>
    /// <param name="lambdaId"> (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the lambda.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LambdaResponse> CreateLambda(Guid? lambdaId, LambdaRequest request) {
      return CreateLambdaAsync(lambdaId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the tenant.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<TenantResponse>> CreateTenantAsync(Guid? tenantId, TenantRequest request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<TenantResponse>();
    }
		
    /// <summary>
    /// Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
    /// </summary>
    /// <param name="tenantId"> (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the tenant.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<TenantResponse> CreateTenant(Guid? tenantId, TenantRequest request) {
      return CreateTenantAsync(tenantId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> (Optional) The Id for the theme. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the theme.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ThemeResponse>> CreateThemeAsync(Guid? themeId, ThemeRequest request) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ThemeResponse>();
    }
		
    /// <summary>
    /// Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
    /// </summary>
    /// <param name="themeId"> (Optional) The Id for the theme. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the theme.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ThemeResponse> CreateTheme(Guid? themeId, ThemeRequest request) {
      return CreateThemeAsync(themeId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> (Optional) The Id for the user. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> CreateUserAsync(Guid? userId, UserRequest request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
    /// </summary>
    /// <param name="userId"> (Optional) The Id for the user. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> CreateUser(Guid? userId, UserRequest request) {
      return CreateUserAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
    /// that the user action can be applied to any user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> (Optional) The Id for the user action. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the user action.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionResponse>> CreateUserActionAsync(Guid? userActionId, UserActionRequest request) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<UserActionResponse>();
    }
		
    /// <summary>
    /// Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
    /// that the user action can be applied to any user.
    /// </summary>
    /// <param name="userActionId"> (Optional) The Id for the user action. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the user action.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionResponse> CreateUserAction(Guid? userActionId, UserActionRequest request) {
      return CreateUserActionAsync(userActionId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
    /// successfully. Anytime after that the user action reason can be used.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the user action reason.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionReasonResponse>> CreateUserActionReasonAsync(Guid? userActionReasonId, UserActionReasonRequest request) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<UserActionReasonResponse>();
    }
		
    /// <summary>
    /// Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
    /// successfully. Anytime after that the user action reason can be used.
    /// </summary>
    /// <param name="userActionReasonId"> (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the user action reason.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionReasonResponse> CreateUserActionReason(Guid? userActionReasonId, UserActionReasonRequest request) {
      return CreateUserActionReasonAsync(userActionReasonId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a single User consent.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request that contains the user consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserConsentResponse>> CreateUserConsentAsync(Guid? userConsentId, UserConsentRequest request) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<UserConsentResponse>();
    }
		
    /// <summary>
    /// Creates a single User consent.
    /// </summary>
    /// <param name="userConsentId"> (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request that contains the user consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserConsentResponse> CreateUserConsent(Guid? userConsentId, UserConsentRequest request) {
      return CreateUserConsentAsync(userConsentId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="webhookId"> (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the webhook.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<WebhookResponse>> CreateWebhookAsync(Guid? webhookId, WebhookRequest request) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<WebhookResponse>();
    }
		
    /// <summary>
    /// Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
    /// </summary>
    /// <param name="webhookId"> (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the webhook.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<WebhookResponse> CreateWebhook(Guid? webhookId, WebhookRequest request) {
      return CreateWebhookAsync(webhookId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deactivates the application with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeactivateApplicationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deactivates the application with the given Id.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeactivateApplication(Guid? applicationId) {
      return DeactivateApplicationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deactivates the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeactivateUserAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deactivates the user with the given Id.
    /// </summary>
    /// <param name="userId"> The Id of the user to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeactivateUser(Guid? userId) {
      return DeactivateUserAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deactivates the user action with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeactivateUserActionAsync(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deactivates the user action with the given Id.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeactivateUserAction(Guid? userActionId) {
      return DeactivateUserActionAsync(userActionId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deactivates the users with the given ids.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userIds"> The ids of the users to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
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
		
    /// <summary>
    /// Deactivates the users with the given ids.
    /// </summary>
    /// <param name="userIds"> The ids of the users to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    [Obsolete("This method has been renamed to DeactivateUsersByIds, use that method instead.")]
    public ClientResponse<UserDeleteResponse> DeactivateUsers(List<string> userIds) {
      return DeactivateUsersAsync(userIds).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deactivates the users with the given ids.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userIds"> The ids of the users to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserDeleteResponse>> DeactivateUsersByIdsAsync(List<string> userIds) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withParameter("userId", userIds)
          .withParameter("dryRun", false)
          .withParameter("hardDelete", false)
          .withMethod("Delete")
          .goAsync<UserDeleteResponse>();
    }
		
    /// <summary>
    /// Deactivates the users with the given ids.
    /// </summary>
    /// <param name="userIds"> The ids of the users to deactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserDeleteResponse> DeactivateUsersByIds(List<string> userIds) {
      return DeactivateUsersByIdsAsync(userIds).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
    /// delete the application, any registrations for that application, metrics and reports for the application, all the
    /// roles for the application, and any other data associated with the application. This operation could take a very
    /// long time, depending on the amount of data in your database.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteApplicationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
    /// delete the application, any registrations for that application, metrics and reports for the application, all the
    /// roles for the application, and any other data associated with the application. This operation could take a very
    /// long time, depending on the amount of data in your database.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteApplication(Guid? applicationId) {
      return DeleteApplicationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
    /// permanently removes the given role from all users that had it.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to deactivate.</param>
    /// <param name="roleId"> The Id of the role to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteApplicationRoleAsync(Guid? applicationId, Guid? roleId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
    /// permanently removes the given role from all users that had it.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to deactivate.</param>
    /// <param name="roleId"> The Id of the role to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteApplicationRole(Guid? applicationId, Guid? roleId) {
      return DeleteApplicationRoleAsync(applicationId, roleId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the consent for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteConsentAsync(Guid? consentId) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the consent for the given Id.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteConsent(Guid? consentId) {
      return DeleteConsentAsync(consentId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the email template for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteEmailTemplateAsync(Guid? emailTemplateId) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the email template for the given Id.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteEmailTemplate(Guid? emailTemplateId) {
      return DeleteEmailTemplateAsync(emailTemplateId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the group for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> The Id of the group to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteGroupAsync(Guid? groupId) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the group for the given Id.
    /// </summary>
    /// <param name="groupId"> The Id of the group to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteGroup(Guid? groupId) {
      return DeleteGroupAsync(groupId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Removes users as members of a group.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The member request that contains all of the information used to remove members to the group.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteGroupMembersAsync(MemberDeleteRequest request) {
      return buildClient()
          .withUri("/api/group/member")
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Removes users as members of a group.
    /// </summary>
    /// <param name="request"> The member request that contains all of the information used to remove members to the group.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteGroupMembers(MemberDeleteRequest request) {
      return DeleteGroupMembersAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the identity provider for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteIdentityProviderAsync(Guid? identityProviderId) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the identity provider for the given Id.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteIdentityProvider(Guid? identityProviderId) {
      return DeleteIdentityProviderAsync(identityProviderId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the key for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyOd"> The Id of the key to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteKeyAsync(Guid? keyOd) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyOd)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the key for the given Id.
    /// </summary>
    /// <param name="keyOd"> The Id of the key to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteKey(Guid? keyOd) {
      return DeleteKeyAsync(keyOd).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the lambda for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteLambdaAsync(Guid? lambdaId) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the lambda for the given Id.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteLambda(Guid? lambdaId) {
      return DeleteLambdaAsync(lambdaId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the user registration for the given user and application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is being deleted.</param>
    /// <param name="applicationId"> The Id of the application to remove the registration for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteRegistrationAsync(Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the user registration for the given user and application.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is being deleted.</param>
    /// <param name="applicationId"> The Id of the application to remove the registration for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteRegistration(Guid? userId, Guid? applicationId) {
      return DeleteRegistrationAsync(userId, applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the tenant for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteTenantAsync(Guid? tenantId) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the tenant for the given Id.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteTenant(Guid? tenantId) {
      return DeleteTenantAsync(tenantId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the theme for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteThemeAsync(Guid? themeId) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the theme for the given Id.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteTheme(Guid? themeId) {
      return DeleteThemeAsync(themeId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
    /// with the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteUserAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
    /// with the user.
    /// </summary>
    /// <param name="userId"> The Id of the user to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteUser(Guid? userId) {
      return DeleteUserAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
    /// the action being applied to any users.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteUserActionAsync(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withParameter("hardDelete", true)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
    /// the action being applied to any users.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteUserAction(Guid? userActionId) {
      return DeleteUserActionAsync(userActionId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the user action reason for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteUserActionReasonAsync(Guid? userActionReasonId) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the user action reason for the given Id.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteUserActionReason(Guid? userActionReasonId) {
      return DeleteUserActionReasonAsync(userActionReasonId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
    /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
    /// 
    /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
    /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The UserDeleteRequest.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    [Obsolete("This method has been renamed to DeleteUsersByQueryAsync, use that method instead.")]
    public Task<ClientResponse<UserDeleteResponse>> DeleteUsersAsync(UserDeleteRequest request) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<UserDeleteResponse>();
    }
		
    /// <summary>
    /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
    /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
    /// 
    /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
    /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
    /// </summary>
    /// <param name="request"> The UserDeleteRequest.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    [Obsolete("This method has been renamed to DeleteUsersByQuery, use that method instead.")]
    public ClientResponse<UserDeleteResponse> DeleteUsers(UserDeleteRequest request) {
      return DeleteUsersAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
    /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
    /// 
    /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
    /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The UserDeleteRequest.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserDeleteResponse>> DeleteUsersByQueryAsync(UserDeleteRequest request) {
      return buildClient()
          .withUri("/api/user/bulk")
          .withJSONBody(request)
          .withMethod("Delete")
          .goAsync<UserDeleteResponse>();
    }
		
    /// <summary>
    /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
    /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
    /// 
    /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
    /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
    /// </summary>
    /// <param name="request"> The UserDeleteRequest.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserDeleteResponse> DeleteUsersByQuery(UserDeleteRequest request) {
      return DeleteUsersByQueryAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Deletes the webhook for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="webhookId"> The Id of the webhook to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DeleteWebhookAsync(Guid? webhookId) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Deletes the webhook for the given Id.
    /// </summary>
    /// <param name="webhookId"> The Id of the webhook to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DeleteWebhook(Guid? webhookId) {
      return DeleteWebhookAsync(webhookId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Disable Two Factor authentication for a user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the User for which you're disabling Two Factor authentication.</param>
    /// <param name="code"> The Two Factor code used verify the the caller knows the Two Factor secret.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> DisableTwoFactorAsync(Guid? userId, string code) {
      return buildClient()
          .withUri("/api/user/two-factor")
          .withParameter("userId", userId)
          .withParameter("code", code)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Disable Two Factor authentication for a user.
    /// </summary>
    /// <param name="userId"> The Id of the User for which you're disabling Two Factor authentication.</param>
    /// <param name="code"> The Two Factor code used verify the the caller knows the Two Factor secret.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> DisableTwoFactor(Guid? userId, string code) {
      return DisableTwoFactorAsync(userId, code).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Enable Two Factor authentication for a user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to enable Two Factor authentication.</param>
    /// <param name="request"> The two factor enable request information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> EnableTwoFactorAsync(Guid? userId, TwoFactorRequest request) {
      return buildClient()
          .withUri("/api/user/two-factor")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Enable Two Factor authentication for a user.
    /// </summary>
    /// <param name="userId"> The Id of the user to enable Two Factor authentication.</param>
    /// <param name="request"> The two factor enable request information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> EnableTwoFactor(Guid? userId, TwoFactorRequest request) {
      return EnableTwoFactorAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Exchanges an OAuth authorization code for an access token.
    /// If you will be using the Authorization Code grant, you will make a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="code"> The authorization code returned on the /oauth2/authorize response.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="redirect_uri"> The URI to redirect to upon a successful request.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
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
		
    /// <summary>
    /// Exchanges an OAuth authorization code for an access token.
    /// If you will be using the Authorization Code grant, you will make a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
    /// </summary>
    /// <param name="code"> The authorization code returned on the /oauth2/authorize response.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="redirect_uri"> The URI to redirect to upon a successful request.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<AccessToken> ExchangeOAuthCodeForAccessToken(string code, string client_id, string client_secret, string redirect_uri) {
      return ExchangeOAuthCodeForAccessTokenAsync(code, client_id, client_secret, redirect_uri).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Exchange a Refresh Token for an Access Token.
    /// If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="refresh_token"> The refresh token that you would like to use to exchange for an access token.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="scope"> (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.</param>
    /// <param name="user_code"> (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
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
		
    /// <summary>
    /// Exchange a Refresh Token for an Access Token.
    /// If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
    /// </summary>
    /// <param name="refresh_token"> The refresh token that you would like to use to exchange for an access token.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="scope"> (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.</param>
    /// <param name="user_code"> (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<AccessToken> ExchangeRefreshTokenForAccessToken(string refresh_token, string client_id, string client_secret, string scope, string user_code) {
      return ExchangeRefreshTokenForAccessTokenAsync(refresh_token, client_id, client_secret, scope, user_code).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Exchange a refresh token for a new JWT.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The refresh request.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RefreshResponse>> ExchangeRefreshTokenForJWTAsync(RefreshRequest request) {
      return buildAnonymousClient()
          .withUri("/api/jwt/refresh")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RefreshResponse>();
    }
		
    /// <summary>
    /// Exchange a refresh token for a new JWT.
    /// </summary>
    /// <param name="request"> The refresh request.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RefreshResponse> ExchangeRefreshTokenForJWT(RefreshRequest request) {
      return ExchangeRefreshTokenForJWTAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Exchange User Credentials for a Token.
    /// If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="username"> The login identifier of the user. The login identifier can be either the email or the username.</param>
    /// <param name="password"> The user’s password.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="scope"> (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.</param>
    /// <param name="user_code"> (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
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
		
    /// <summary>
    /// Exchange User Credentials for a Token.
    /// If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
    /// </summary>
    /// <param name="username"> The login identifier of the user. The login identifier can be either the email or the username.</param>
    /// <param name="password"> The user’s password.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you you are attempting to authenticate. This parameter is optional when the Authorization header is provided.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="scope"> (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.</param>
    /// <param name="user_code"> (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<AccessToken> ExchangeUserCredentialsForAccessToken(string username, string password, string client_id, string client_secret, string scope, string user_code) {
      return ExchangeUserCredentialsForAccessTokenAsync(username, password, client_id, client_secret, scope, user_code).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the information about the user so that they can be emailed.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ForgotPasswordResponse>> ForgotPasswordAsync(ForgotPasswordRequest request) {
      return buildClient()
          .withUri("/api/user/forgot-password")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<ForgotPasswordResponse>();
    }
		
    /// <summary>
    /// Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
    /// </summary>
    /// <param name="request"> The request that contains the information about the user so that they can be emailed.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ForgotPasswordResponse> ForgotPassword(ForgotPasswordRequest request) {
      return ForgotPasswordAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
    /// email to the User. This API may be used to collect the verificationId for use with a third party system.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<VerifyEmailResponse>> GenerateEmailVerificationIdAsync(string email) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withParameter("email", email)
          .withParameter("sendVerifyEmail", false)
          .withMethod("Put")
          .goAsync<VerifyEmailResponse>();
    }
		
    /// <summary>
    /// Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
    /// email to the User. This API may be used to collect the verificationId for use with a third party system.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<VerifyEmailResponse> GenerateEmailVerificationId(string email) {
      return GenerateEmailVerificationIdAsync(email).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Generate a new RSA or EC key pair or an HMAC secret.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> (Optional) The Id for the key. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the key.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<KeyResponse>> GenerateKeyAsync(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key/generate")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<KeyResponse>();
    }
		
    /// <summary>
    /// Generate a new RSA or EC key pair or an HMAC secret.
    /// </summary>
    /// <param name="keyId"> (Optional) The Id for the key. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the key.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<KeyResponse> GenerateKey(Guid? keyId, KeyRequest request) {
      return GenerateKeyAsync(keyId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
    /// email to the User. This API may be used to collect the verificationId for use with a third party system.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <param name="applicationId"> The Id of the application to be verified.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<VerifyRegistrationResponse>> GenerateRegistrationVerificationIdAsync(string email, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/verify-registration")
          .withParameter("email", email)
          .withParameter("sendVerifyPasswordEmail", false)
          .withParameter("applicationId", applicationId)
          .withMethod("Put")
          .goAsync<VerifyRegistrationResponse>();
    }
		
    /// <summary>
    /// Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
    /// email to the User. This API may be used to collect the verificationId for use with a third party system.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <param name="applicationId"> The Id of the application to be verified.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<VerifyRegistrationResponse> GenerateRegistrationVerificationId(string email, Guid? applicationId) {
      return GenerateRegistrationVerificationIdAsync(email, applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
    /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
    /// application such as Google Authenticator.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<SecretResponse>> GenerateTwoFactorSecretAsync() {
      return buildClient()
          .withUri("/api/two-factor/secret")
          .withMethod("Get")
          .goAsync<SecretResponse>();
    }
		
    /// <summary>
    /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
    /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
    /// application such as Google Authenticator.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<SecretResponse> GenerateTwoFactorSecret() {
      return GenerateTwoFactorSecretAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
    /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
    /// application such as Google Authenticator.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<SecretResponse>> GenerateTwoFactorSecretUsingJWTAsync(string encodedJWT) {
      return buildClient()
          .withUri("/api/two-factor/secret")
          .withAuthorization("JWT " + encodedJWT)
          .withMethod("Get")
          .goAsync<SecretResponse>();
    }
		
    /// <summary>
    /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
    /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
    /// application such as Google Authenticator.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<SecretResponse> GenerateTwoFactorSecretUsingJWT(string encodedJWT) {
      return GenerateTwoFactorSecretUsingJWTAsync(encodedJWT).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
    /// login systems.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The third-party login request that contains information from the third-party login
    /// providers that FusionAuth uses to reconcile the user's account.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LoginResponse>> IdentityProviderLoginAsync(IdentityProviderLoginRequest request) {
      return buildAnonymousClient()
          .withUri("/api/identity-provider/login")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }
		
    /// <summary>
    /// Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
    /// login systems.
    /// </summary>
    /// <param name="request"> The third-party login request that contains information from the third-party login
     /// providers that FusionAuth uses to reconcile the user's account.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginResponse> IdentityProviderLogin(IdentityProviderLoginRequest request) {
      return IdentityProviderLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Import an existing RSA or EC key pair or an HMAC secret.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> (Optional) The Id for the key. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the key.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<KeyResponse>> ImportKeyAsync(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key/import")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<KeyResponse>();
    }
		
    /// <summary>
    /// Import an existing RSA or EC key pair or an HMAC secret.
    /// </summary>
    /// <param name="keyId"> (Optional) The Id for the key. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all of the information used to create the key.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<KeyResponse> ImportKey(Guid? keyId, KeyRequest request) {
      return ImportKeyAsync(keyId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Bulk imports multiple users. This does some validation, but then tries to run batch inserts of users. This reduces
    /// latency when inserting lots of users. Therefore, the error response might contain some information about failures,
    /// but it will likely be pretty generic.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains all of the information about all of the users to import.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> ImportUsersAsync(ImportRequest request) {
      return buildClient()
          .withUri("/api/user/import")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Bulk imports multiple users. This does some validation, but then tries to run batch inserts of users. This reduces
    /// latency when inserting lots of users. Therefore, the error response might contain some information about failures,
    /// but it will likely be pretty generic.
    /// </summary>
    /// <param name="request"> The request that contains all of the information about all of the users to import.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> ImportUsers(ImportRequest request) {
      return ImportUsersAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
    /// access token is properly signed and not expired.
    /// <p>
    /// This API may be used in an SSO configuration to issue new tokens for another application after the user has
    /// obtained a valid token from authentication.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Application Id for which you are requesting a new access token be issued.</param>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IssueResponse>> IssueJWTAsync(Guid? applicationId, string encodedJWT) {
      return buildClient()
          .withUri("/api/jwt/issue")
          .withAuthorization("JWT " + encodedJWT)
          .withParameter("applicationId", applicationId)
          .withMethod("Get")
          .goAsync<IssueResponse>();
    }
		
    /// <summary>
    /// Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
    /// access token is properly signed and not expired.
    /// <p>
    /// This API may be used in an SSO configuration to issue new tokens for another application after the user has
    /// obtained a valid token from authentication.
    /// </summary>
    /// <param name="applicationId"> The Application Id for which you are requesting a new access token be issued.</param>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IssueResponse> IssueJWT(Guid? applicationId, string encodedJWT) {
      return IssueJWTAsync(applicationId, encodedJWT).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Authenticates a user to FusionAuth. 
    /// 
    /// This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LoginResponse>> LoginAsync(LoginRequest request) {
      return buildClient()
          .withUri("/api/login")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }
		
    /// <summary>
    /// Authenticates a user to FusionAuth. 
    /// 
    /// This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
    /// </summary>
    /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginResponse> Login(LoginRequest request) {
      return LoginAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
    /// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
    /// application where they no longer have a session. This helps correctly track login counts, times and helps with
    /// reporting.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user that was logged in.</param>
    /// <param name="applicationId"> The Id of the application that they logged into.</param>
    /// <param name="callerIPAddress"> (Optional) The IP address of the end-user that is logging in. If a null value is provided
    /// the IP address will be that of the client or last proxy that sent the request.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> LoginPingAsync(Guid? userId, Guid? applicationId, string callerIPAddress) {
      return buildClient()
          .withUri("/api/login")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withParameter("ipAddress", callerIPAddress)
          .withMethod("Put")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
    /// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
    /// application where they no longer have a session. This helps correctly track login counts, times and helps with
    /// reporting.
    /// </summary>
    /// <param name="userId"> The Id of the user that was logged in.</param>
    /// <param name="applicationId"> The Id of the application that they logged into.</param>
    /// <param name="callerIPAddress"> (Optional) The IP address of the end-user that is logging in. If a null value is provided
     /// the IP address will be that of the client or last proxy that sent the request.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> LoginPing(Guid? userId, Guid? applicationId, string callerIPAddress) {
      return LoginPingAsync(userId, applicationId, callerIPAddress).GetAwaiter().GetResult();
    }

    /// <summary>
    /// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
    /// client and revoke the refresh token stored. This API does nothing if the request does not contain an access
    /// token or refresh token cookies.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="global"> When this value is set to true all of the refresh tokens issued to the owner of the
    /// provided token will be revoked.</param>
    /// <param name="refreshToken"> (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
    /// If provided this takes precedence over the cookie.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> LogoutAsync(bool? global, string refreshToken) {
      return buildAnonymousClient()
          .withUri("/api/logout")
          .withParameter("global", global)
          .withParameter("refreshToken", refreshToken)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
    /// client and revoke the refresh token stored. This API does nothing if the request does not contain an access
    /// token or refresh token cookies.
    /// </summary>
    /// <param name="global"> When this value is set to true all of the refresh tokens issued to the owner of the
     /// provided token will be revoked.</param>
    /// <param name="refreshToken"> (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
     /// If provided this takes precedence over the cookie.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> Logout(bool? global, string refreshToken) {
      return LogoutAsync(global, refreshToken).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
    /// by a registered identity provider. A 404 indicates the domain is not managed.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="domain"> The domain or email address to lookup.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LookupResponse>> LookupIdentityProviderAsync(string domain) {
      return buildClient()
          .withUri("/api/identity-provider/lookup")
          .withParameter("domain", domain)
          .withMethod("Get")
          .goAsync<LookupResponse>();
    }
		
    /// <summary>
    /// Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
    /// by a registered identity provider. A 404 indicates the domain is not managed.
    /// </summary>
    /// <param name="domain"> The domain or email address to lookup.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LookupResponse> LookupIdentityProvider(string domain) {
      return LookupIdentityProviderAsync(domain).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
    /// action.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="actionId"> The Id of the action to modify. This is technically the user action log id.</param>
    /// <param name="request"> The request that contains all of the information about the modification.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ActionResponse>> ModifyActionAsync(Guid? actionId, ActionRequest request) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ActionResponse>();
    }
		
    /// <summary>
    /// Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
    /// action.
    /// </summary>
    /// <param name="actionId"> The Id of the action to modify. This is technically the user action log id.</param>
    /// <param name="request"> The request that contains all of the information about the modification.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ActionResponse> ModifyAction(Guid? actionId, ActionRequest request) {
      return ModifyActionAsync(actionId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Complete a login request using a passwordless code
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The passwordless login request that contains all of the information used to complete login.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LoginResponse>> PasswordlessLoginAsync(PasswordlessLoginRequest request) {
      return buildAnonymousClient()
          .withUri("/api/passwordless/login")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }
		
    /// <summary>
    /// Complete a login request using a passwordless code
    /// </summary>
    /// <param name="request"> The passwordless login request that contains all of the information used to complete login.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginResponse> PasswordlessLogin(PasswordlessLoginRequest request) {
      return PasswordlessLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the application with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to update.</param>
    /// <param name="request"> The request that contains just the new application information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ApplicationResponse>> PatchApplicationAsync(Guid? applicationId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ApplicationResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the application with the given Id.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to update.</param>
    /// <param name="request"> The request that contains just the new application information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> PatchApplication(Guid? applicationId, Dictionary<string, object> request) {
      return PatchApplicationAsync(applicationId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the application role with the given id for the application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
    /// <param name="roleId"> The Id of the role to update.</param>
    /// <param name="request"> The request that contains just the new role information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ApplicationResponse>> PatchApplicationRoleAsync(Guid? applicationId, Guid? roleId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("role")
          .withUriSegment(roleId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ApplicationResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the application role with the given id for the application.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
    /// <param name="roleId"> The Id of the role to update.</param>
    /// <param name="request"> The request that contains just the new role information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> PatchApplicationRole(Guid? applicationId, Guid? roleId, Dictionary<string, object> request) {
      return PatchApplicationRoleAsync(applicationId, roleId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the consent with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to update.</param>
    /// <param name="request"> The request that contains just the new consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ConsentResponse>> PatchConsentAsync(Guid? consentId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ConsentResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the consent with the given Id.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to update.</param>
    /// <param name="request"> The request that contains just the new consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ConsentResponse> PatchConsent(Guid? consentId, Dictionary<string, object> request) {
      return PatchConsentAsync(consentId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the email template with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to update.</param>
    /// <param name="request"> The request that contains just the new email template information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<EmailTemplateResponse>> PatchEmailTemplateAsync(Guid? emailTemplateId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<EmailTemplateResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the email template with the given Id.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to update.</param>
    /// <param name="request"> The request that contains just the new email template information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<EmailTemplateResponse> PatchEmailTemplate(Guid? emailTemplateId, Dictionary<string, object> request) {
      return PatchEmailTemplateAsync(emailTemplateId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the group with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> The Id of the group to update.</param>
    /// <param name="request"> The request that contains just the new group information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<GroupResponse>> PatchGroupAsync(Guid? groupId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<GroupResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the group with the given Id.
    /// </summary>
    /// <param name="groupId"> The Id of the group to update.</param>
    /// <param name="request"> The request that contains just the new group information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<GroupResponse> PatchGroup(Guid? groupId, Dictionary<string, object> request) {
      return PatchGroupAsync(groupId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the identity provider with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to update.</param>
    /// <param name="request"> The request object that contains just the updated identity provider information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IdentityProviderResponse>> PatchIdentityProviderAsync(Guid? identityProviderId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<IdentityProviderResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the identity provider with the given Id.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to update.</param>
    /// <param name="request"> The request object that contains just the updated identity provider information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IdentityProviderResponse> PatchIdentityProvider(Guid? identityProviderId, Dictionary<string, object> request) {
      return PatchIdentityProviderAsync(identityProviderId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the available integrations.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains just the new integration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IntegrationResponse>> PatchIntegrationsAsync(Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/integration")
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<IntegrationResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the available integrations.
    /// </summary>
    /// <param name="request"> The request that contains just the new integration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IntegrationResponse> PatchIntegrations(Dictionary<string, object> request) {
      return PatchIntegrationsAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the lambda with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to update.</param>
    /// <param name="request"> The request that contains just the new lambda information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LambdaResponse>> PatchLambdaAsync(Guid? lambdaId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<LambdaResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the lambda with the given Id.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to update.</param>
    /// <param name="request"> The request that contains just the new lambda information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LambdaResponse> PatchLambda(Guid? lambdaId, Dictionary<string, object> request) {
      return PatchLambdaAsync(lambdaId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the registration for the user with the given id and the application defined in the request.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is going to be updated.</param>
    /// <param name="request"> The request that contains just the new registration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RegistrationResponse>> PatchRegistrationAsync(Guid? userId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<RegistrationResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the registration for the user with the given id and the application defined in the request.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is going to be updated.</param>
    /// <param name="request"> The request that contains just the new registration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RegistrationResponse> PatchRegistration(Guid? userId, Dictionary<string, object> request) {
      return PatchRegistrationAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the system configuration.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains just the new system configuration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<SystemConfigurationResponse>> PatchSystemConfigurationAsync(Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/system-configuration")
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<SystemConfigurationResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the system configuration.
    /// </summary>
    /// <param name="request"> The request that contains just the new system configuration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<SystemConfigurationResponse> PatchSystemConfiguration(Dictionary<string, object> request) {
      return PatchSystemConfigurationAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the tenant with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to update.</param>
    /// <param name="request"> The request that contains just the new tenant information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<TenantResponse>> PatchTenantAsync(Guid? tenantId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<TenantResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the tenant with the given Id.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to update.</param>
    /// <param name="request"> The request that contains just the new tenant information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<TenantResponse> PatchTenant(Guid? tenantId, Dictionary<string, object> request) {
      return PatchTenantAsync(tenantId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the theme with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to update.</param>
    /// <param name="request"> The request that contains just the new theme information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ThemeResponse>> PatchThemeAsync(Guid? themeId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<ThemeResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the theme with the given Id.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to update.</param>
    /// <param name="request"> The request that contains just the new theme information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ThemeResponse> PatchTheme(Guid? themeId, Dictionary<string, object> request) {
      return PatchThemeAsync(themeId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to update.</param>
    /// <param name="request"> The request that contains just the new user information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> PatchUserAsync(Guid? userId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the user with the given Id.
    /// </summary>
    /// <param name="userId"> The Id of the user to update.</param>
    /// <param name="request"> The request that contains just the new user information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> PatchUser(Guid? userId, Dictionary<string, object> request) {
      return PatchUserAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the user action with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to update.</param>
    /// <param name="request"> The request that contains just the new user action information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionResponse>> PatchUserActionAsync(Guid? userActionId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<UserActionResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the user action with the given Id.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to update.</param>
    /// <param name="request"> The request that contains just the new user action information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionResponse> PatchUserAction(Guid? userActionId, Dictionary<string, object> request) {
      return PatchUserActionAsync(userActionId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, the user action reason with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to update.</param>
    /// <param name="request"> The request that contains just the new user action reason information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionReasonResponse>> PatchUserActionReasonAsync(Guid? userActionReasonId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<UserActionReasonResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, the user action reason with the given Id.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to update.</param>
    /// <param name="request"> The request that contains just the new user action reason information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionReasonResponse> PatchUserActionReason(Guid? userActionReasonId, Dictionary<string, object> request) {
      return PatchUserActionReasonAsync(userActionReasonId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates, via PATCH, a single User consent by Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <param name="request"> The request that contains just the new user consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserConsentResponse>> PatchUserConsentAsync(Guid? userConsentId, Dictionary<string, object> request) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withJSONBody(request)
          .withMethod("Patch")
          .goAsync<UserConsentResponse>();
    }
		
    /// <summary>
    /// Updates, via PATCH, a single User consent by Id.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <param name="request"> The request that contains just the new user consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserConsentResponse> PatchUserConsent(Guid? userConsentId, Dictionary<string, object> request) {
      return PatchUserConsentAsync(userConsentId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Reactivates the application with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to reactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ApplicationResponse>> ReactivateApplicationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .goAsync<ApplicationResponse>();
    }
		
    /// <summary>
    /// Reactivates the application with the given Id.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to reactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> ReactivateApplication(Guid? applicationId) {
      return ReactivateApplicationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Reactivates the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to reactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> ReactivateUserAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Reactivates the user with the given Id.
    /// </summary>
    /// <param name="userId"> The Id of the user to reactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> ReactivateUser(Guid? userId) {
      return ReactivateUserAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Reactivates the user action with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to reactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionResponse>> ReactivateUserActionAsync(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withParameter("reactivate", true)
          .withMethod("Put")
          .goAsync<UserActionResponse>();
    }
		
    /// <summary>
    /// Reactivates the user action with the given Id.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to reactivate.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionResponse> ReactivateUserAction(Guid? userActionId) {
      return ReactivateUserActionAsync(userActionId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The reconcile request that contains the data to reconcile the User.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LoginResponse>> ReconcileJWTAsync(IdentityProviderLoginRequest request) {
      return buildAnonymousClient()
          .withUri("/api/jwt/reconcile")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }
		
    /// <summary>
    /// Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
    /// </summary>
    /// <param name="request"> The reconcile request that contains the data to reconcile the User.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginResponse> ReconcileJWT(IdentityProviderLoginRequest request) {
      return ReconcileJWTAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
    /// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
    /// if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
    ///  ensure the index immediately current before making a query request to the search index.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> RefreshUserSearchIndexAsync() {
      return buildClient()
          .withUri("/api/user/search")
          .withMethod("Put")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
    /// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
    /// if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
    ///  ensure the index immediately current before making a query request to the search index.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> RefreshUserSearchIndex() {
      return RefreshUserSearchIndexAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
    /// will create the user as well as register them for the application. This is called a Full Registration. However, if
    /// you only provide the UserRegistration object, then the user must already exist and they will be registered for the
    /// application. The user id can also be provided and it will either be used to look up an existing user or it will be
    /// used for the newly created User.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> (Optional) The Id of the user being registered for the application and optionally created.</param>
    /// <param name="request"> The request that optionally contains the User and must contain the UserRegistration.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RegistrationResponse>> RegisterAsync(Guid? userId, RegistrationRequest request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RegistrationResponse>();
    }
		
    /// <summary>
    /// Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
    /// will create the user as well as register them for the application. This is called a Full Registration. However, if
    /// you only provide the UserRegistration object, then the user must already exist and they will be registered for the
    /// application. The user id can also be provided and it will either be used to look up an existing user or it will be
    /// used for the newly created User.
    /// </summary>
    /// <param name="userId"> (Optional) The Id of the user being registered for the application and optionally created.</param>
    /// <param name="request"> The request that optionally contains the User and must contain the UserRegistration.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RegistrationResponse> Register(Guid? userId, RegistrationRequest request) {
      return RegisterAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Removes a user from the family with the given id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="familyId"> The id of the family to remove the user from.</param>
    /// <param name="userId"> The id of the user to remove from the family.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> RemoveUserFromFamilyAsync(Guid? familyId, Guid? userId) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withUriSegment(userId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Removes a user from the family with the given id.
    /// </summary>
    /// <param name="familyId"> The id of the family to remove the user from.</param>
    /// <param name="userId"> The id of the user to remove from the family.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> RemoveUserFromFamily(Guid? familyId, Guid? userId) {
      return RemoveUserFromFamilyAsync(familyId, userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Re-sends the verification email to the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<VerifyEmailResponse>> ResendEmailVerificationAsync(string email) {
      return buildClient()
          .withUri("/api/user/verify-email")
          .withParameter("email", email)
          .withMethod("Put")
          .goAsync<VerifyEmailResponse>();
    }
		
    /// <summary>
    /// Re-sends the verification email to the user.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<VerifyEmailResponse> ResendEmailVerification(string email) {
      return ResendEmailVerificationAsync(email).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Re-sends the application registration verification email to the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <param name="applicationId"> The Id of the application to be verified.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<VerifyRegistrationResponse>> ResendRegistrationVerificationAsync(string email, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/verify-registration")
          .withParameter("email", email)
          .withParameter("applicationId", applicationId)
          .withMethod("Put")
          .goAsync<VerifyRegistrationResponse>();
    }
		
    /// <summary>
    /// Re-sends the application registration verification email to the user.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <param name="applicationId"> The Id of the application to be verified.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<VerifyRegistrationResponse> ResendRegistrationVerification(string email, Guid? applicationId) {
      return ResendRegistrationVerificationAsync(email, applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="actionId"> The Id of the action to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ActionResponse>> RetrieveActionAsync(Guid? actionId) {
      return buildClient()
          .withUri("/api/user/action")
          .withUriSegment(actionId)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }
		
    /// <summary>
    /// Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
    /// </summary>
    /// <param name="actionId"> The Id of the action to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ActionResponse> RetrieveAction(Guid? actionId) {
      return RetrieveActionAsync(actionId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the actions for the user with the given Id. This will return all time based actions that are active,
    /// and inactive as well as non-time based actions.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ActionResponse>> RetrieveActionsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the actions for the user with the given Id. This will return all time based actions that are active,
    /// and inactive as well as non-time based actions.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ActionResponse> RetrieveActions(Guid? userId) {
      return RetrieveActionsAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the actions for the user with the given Id that are currently preventing the User from logging in.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ActionResponse>> RetrieveActionsPreventingLoginAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("preventingLogin", true)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the actions for the user with the given Id that are currently preventing the User from logging in.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ActionResponse> RetrieveActionsPreventingLogin(Guid? userId) {
      return RetrieveActionsPreventingLoginAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the actions for the user with the given Id that are currently active.
    /// An active action means one that is time based and has not been canceled, and has not ended.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ActionResponse>> RetrieveActiveActionsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("active", true)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the actions for the user with the given Id that are currently active.
    /// An active action means one that is time based and has not been canceled, and has not ended.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ActionResponse> RetrieveActiveActions(Guid? userId) {
      return RetrieveActiveActionsAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the application for the given id or all of the applications if the id is null.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ApplicationResponse>> RetrieveApplicationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withMethod("Get")
          .goAsync<ApplicationResponse>();
    }
		
    /// <summary>
    /// Retrieves the application for the given id or all of the applications if the id is null.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> RetrieveApplication(Guid? applicationId) {
      return RetrieveApplicationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the applications.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ApplicationResponse>> RetrieveApplicationsAsync() {
      return buildClient()
          .withUri("/api/application")
          .withMethod("Get")
          .goAsync<ApplicationResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the applications.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> RetrieveApplications() {
      return RetrieveApplicationsAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves a single audit log for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="auditLogId"> The Id of the audit log to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<AuditLogResponse>> RetrieveAuditLogAsync(int? auditLogId) {
      return buildClient()
          .withUri("/api/system/audit-log")
          .withUriSegment(auditLogId)
          .withMethod("Get")
          .goAsync<AuditLogResponse>();
    }
		
    /// <summary>
    /// Retrieves a single audit log for the given Id.
    /// </summary>
    /// <param name="auditLogId"> The Id of the audit log to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<AuditLogResponse> RetrieveAuditLog(int? auditLogId) {
      return RetrieveAuditLogAsync(auditLogId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the Consent for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> The Id of the consent.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ConsentResponse>> RetrieveConsentAsync(Guid? consentId) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withMethod("Get")
          .goAsync<ConsentResponse>();
    }
		
    /// <summary>
    /// Retrieves the Consent for the given Id.
    /// </summary>
    /// <param name="consentId"> The Id of the consent.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ConsentResponse> RetrieveConsent(Guid? consentId) {
      return RetrieveConsentAsync(consentId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the consent.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ConsentResponse>> RetrieveConsentsAsync() {
      return buildClient()
          .withUri("/api/consent")
          .withMethod("Get")
          .goAsync<ConsentResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the consent.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ConsentResponse> RetrieveConsents() {
      return RetrieveConsentsAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the daily active user report between the two instants. If you specify an application id, it will only
    /// return the daily active counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<DailyActiveUserReportResponse>> RetrieveDailyActiveReportAsync(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/daily-active-user")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<DailyActiveUserReportResponse>();
    }
		
    /// <summary>
    /// Retrieves the daily active user report between the two instants. If you specify an application id, it will only
    /// return the daily active counts for that application.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<DailyActiveUserReportResponse> RetrieveDailyActiveReport(Guid? applicationId, long? start, long? end) {
      return RetrieveDailyActiveReportAsync(applicationId, start, end).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the email template for the given Id. If you don't specify the id, this will return all of the email templates.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> (Optional) The Id of the email template.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<EmailTemplateResponse>> RetrieveEmailTemplateAsync(Guid? emailTemplateId) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withMethod("Get")
          .goAsync<EmailTemplateResponse>();
    }
		
    /// <summary>
    /// Retrieves the email template for the given Id. If you don't specify the id, this will return all of the email templates.
    /// </summary>
    /// <param name="emailTemplateId"> (Optional) The Id of the email template.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<EmailTemplateResponse> RetrieveEmailTemplate(Guid? emailTemplateId) {
      return RetrieveEmailTemplateAsync(emailTemplateId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates a preview of the email template provided in the request. This allows you to preview an email template that
    /// hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
    /// will create the preview based on whatever is given.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the email template and optionally a locale to render it in.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<PreviewResponse>> RetrieveEmailTemplatePreviewAsync(PreviewRequest request) {
      return buildClient()
          .withUri("/api/email/template/preview")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<PreviewResponse>();
    }
		
    /// <summary>
    /// Creates a preview of the email template provided in the request. This allows you to preview an email template that
    /// hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
    /// will create the preview based on whatever is given.
    /// </summary>
    /// <param name="request"> The request that contains the email template and optionally a locale to render it in.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<PreviewResponse> RetrieveEmailTemplatePreview(PreviewRequest request) {
      return RetrieveEmailTemplatePreviewAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the email templates.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<EmailTemplateResponse>> RetrieveEmailTemplatesAsync() {
      return buildClient()
          .withUri("/api/email/template")
          .withMethod("Get")
          .goAsync<EmailTemplateResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the email templates.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<EmailTemplateResponse> RetrieveEmailTemplates() {
      return RetrieveEmailTemplatesAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves a single event log for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="eventLogId"> The Id of the event log to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<EventLogResponse>> RetrieveEventLogAsync(int? eventLogId) {
      return buildClient()
          .withUri("/api/system/event-log")
          .withUriSegment(eventLogId)
          .withMethod("Get")
          .goAsync<EventLogResponse>();
    }
		
    /// <summary>
    /// Retrieves a single event log for the given Id.
    /// </summary>
    /// <param name="eventLogId"> The Id of the event log to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<EventLogResponse> RetrieveEventLog(int? eventLogId) {
      return RetrieveEventLogAsync(eventLogId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the families that a user belongs to.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The User's id</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<FamilyResponse>> RetrieveFamiliesAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/family")
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<FamilyResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the families that a user belongs to.
    /// </summary>
    /// <param name="userId"> The User's id</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<FamilyResponse> RetrieveFamilies(Guid? userId) {
      return RetrieveFamiliesAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the members of a family by the unique Family Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="familyId"> The unique Id of the Family.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<FamilyResponse>> RetrieveFamilyMembersByFamilyIdAsync(Guid? familyId) {
      return buildClient()
          .withUri("/api/user/family")
          .withUriSegment(familyId)
          .withMethod("Get")
          .goAsync<FamilyResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the members of a family by the unique Family Id.
    /// </summary>
    /// <param name="familyId"> The unique Id of the Family.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<FamilyResponse> RetrieveFamilyMembersByFamilyId(Guid? familyId) {
      return RetrieveFamilyMembersByFamilyIdAsync(familyId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the group for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> The Id of the group.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<GroupResponse>> RetrieveGroupAsync(Guid? groupId) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withMethod("Get")
          .goAsync<GroupResponse>();
    }
		
    /// <summary>
    /// Retrieves the group for the given Id.
    /// </summary>
    /// <param name="groupId"> The Id of the group.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<GroupResponse> RetrieveGroup(Guid? groupId) {
      return RetrieveGroupAsync(groupId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the groups.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<GroupResponse>> RetrieveGroupsAsync() {
      return buildClient()
          .withUri("/api/group")
          .withMethod("Get")
          .goAsync<GroupResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the groups.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<GroupResponse> RetrieveGroups() {
      return RetrieveGroupsAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the identity provider for the given id or all of the identity providers if the id is null.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> (Optional) The identity provider id.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IdentityProviderResponse>> RetrieveIdentityProviderAsync(Guid? identityProviderId) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withMethod("Get")
          .goAsync<IdentityProviderResponse>();
    }
		
    /// <summary>
    /// Retrieves the identity provider for the given id or all of the identity providers if the id is null.
    /// </summary>
    /// <param name="identityProviderId"> (Optional) The identity provider id.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IdentityProviderResponse> RetrieveIdentityProvider(Guid? identityProviderId) {
      return RetrieveIdentityProviderAsync(identityProviderId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the identity providers.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IdentityProviderResponse>> RetrieveIdentityProvidersAsync() {
      return buildClient()
          .withUri("/api/identity-provider")
          .withMethod("Get")
          .goAsync<IdentityProviderResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the identity providers.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IdentityProviderResponse> RetrieveIdentityProviders() {
      return RetrieveIdentityProvidersAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the actions for the user with the given Id that are currently inactive.
    /// An inactive action means one that is time based and has been canceled or has expired, or is not time based.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ActionResponse>> RetrieveInactiveActionsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/action")
          .withParameter("userId", userId)
          .withParameter("active", false)
          .withMethod("Get")
          .goAsync<ActionResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the actions for the user with the given Id that are currently inactive.
    /// An inactive action means one that is time based and has been canceled or has expired, or is not time based.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ActionResponse> RetrieveInactiveActions(Guid? userId) {
      return RetrieveInactiveActionsAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the applications that are currently inactive.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ApplicationResponse>> RetrieveInactiveApplicationsAsync() {
      return buildClient()
          .withUri("/api/application")
          .withParameter("inactive", true)
          .withMethod("Get")
          .goAsync<ApplicationResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the applications that are currently inactive.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> RetrieveInactiveApplications() {
      return RetrieveInactiveApplicationsAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the user actions that are currently inactive.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionResponse>> RetrieveInactiveUserActionsAsync() {
      return buildClient()
          .withUri("/api/user-action")
          .withParameter("inactive", true)
          .withMethod("Get")
          .goAsync<UserActionResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the user actions that are currently inactive.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionResponse> RetrieveInactiveUserActions() {
      return RetrieveInactiveUserActionsAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the available integrations.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IntegrationResponse>> RetrieveIntegrationAsync() {
      return buildClient()
          .withUri("/api/integration")
          .withMethod("Get")
          .goAsync<IntegrationResponse>();
    }
		
    /// <summary>
    /// Retrieves the available integrations.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IntegrationResponse> RetrieveIntegration() {
      return RetrieveIntegrationAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the public key (kid).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeyAsync(string keyId) {
      return buildAnonymousClient()
          .withUri("/api/jwt/public-key")
          .withParameter("kid", keyId)
          .withMethod("Get")
          .goAsync<PublicKeyResponse>();
    }
		
    /// <summary>
    /// Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
    /// </summary>
    /// <param name="keyId"> The Id of the public key (kid).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKey(string keyId) {
      return RetrieveJWTPublicKeyAsync(keyId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the Application for which this key is used.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeyByApplicationIdAsync(string applicationId) {
      return buildAnonymousClient()
          .withUri("/api/jwt/public-key")
          .withParameter("applicationId", applicationId)
          .withMethod("Get")
          .goAsync<PublicKeyResponse>();
    }
		
    /// <summary>
    /// Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
    /// </summary>
    /// <param name="applicationId"> The Id of the Application for which this key is used.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKeyByApplicationId(string applicationId) {
      return RetrieveJWTPublicKeyByApplicationIdAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeysAsync() {
      return buildAnonymousClient()
          .withUri("/api/jwt/public-key")
          .withMethod("Get")
          .goAsync<PublicKeyResponse>();
    }
		
    /// <summary>
    /// Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKeys() {
      return RetrieveJWTPublicKeysAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<JWKSResponse>> RetrieveJsonWebKeySetAsync() {
      return buildAnonymousClient()
          .withUri("/.well-known/jwks.json")
          .withMethod("Get")
          .goAsync<JWKSResponse>();
    }
		
    /// <summary>
    /// Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<JWKSResponse> RetrieveJsonWebKeySet() {
      return RetrieveJsonWebKeySetAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the key for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the key.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<KeyResponse>> RetrieveKeyAsync(Guid? keyId) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyId)
          .withMethod("Get")
          .goAsync<KeyResponse>();
    }
		
    /// <summary>
    /// Retrieves the key for the given Id.
    /// </summary>
    /// <param name="keyId"> The Id of the key.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<KeyResponse> RetrieveKey(Guid? keyId) {
      return RetrieveKeyAsync(keyId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the keys.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<KeyResponse>> RetrieveKeysAsync() {
      return buildClient()
          .withUri("/api/key")
          .withMethod("Get")
          .goAsync<KeyResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the keys.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<KeyResponse> RetrieveKeys() {
      return RetrieveKeysAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the lambda for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LambdaResponse>> RetrieveLambdaAsync(Guid? lambdaId) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withMethod("Get")
          .goAsync<LambdaResponse>();
    }
		
    /// <summary>
    /// Retrieves the lambda for the given Id.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LambdaResponse> RetrieveLambda(Guid? lambdaId) {
      return RetrieveLambdaAsync(lambdaId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the lambdas.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LambdaResponse>> RetrieveLambdasAsync() {
      return buildClient()
          .withUri("/api/lambda")
          .withMethod("Get")
          .goAsync<LambdaResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the lambdas.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LambdaResponse> RetrieveLambdas() {
      return RetrieveLambdasAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the lambdas for the provided type.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="type"> The type of the lambda to return.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LambdaResponse>> RetrieveLambdasByTypeAsync(LambdaType type) {
      return buildClient()
          .withUri("/api/lambda")
          .withParameter("type", type)
          .withMethod("Get")
          .goAsync<LambdaResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the lambdas for the provided type.
    /// </summary>
    /// <param name="type"> The type of the lambda to return.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LambdaResponse> RetrieveLambdasByType(LambdaType type) {
      return RetrieveLambdasByTypeAsync(type).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the login report between the two instants. If you specify an application id, it will only return the
    /// login counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LoginReportResponse>> RetrieveLoginReportAsync(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/login")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<LoginReportResponse>();
    }
		
    /// <summary>
    /// Retrieves the login report between the two instants. If you specify an application id, it will only return the
    /// login counts for that application.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginReportResponse> RetrieveLoginReport(Guid? applicationId, long? start, long? end) {
      return RetrieveLoginReportAsync(applicationId, start, end).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
    /// return the monthly active counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<MonthlyActiveUserReportResponse>> RetrieveMonthlyActiveReportAsync(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/monthly-active-user")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<MonthlyActiveUserReportResponse>();
    }
		
    /// <summary>
    /// Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
    /// return the monthly active counts for that application.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<MonthlyActiveUserReportResponse> RetrieveMonthlyActiveReport(Guid? applicationId, long? start, long? end) {
      return RetrieveMonthlyActiveReportAsync(applicationId, start, end).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the Oauth2 configuration for the application for the given Application Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the Application to retrieve OAuth configuration.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<OAuthConfigurationResponse>> RetrieveOauthConfigurationAsync(Guid? applicationId) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withUriSegment("oauth-configuration")
          .withMethod("Get")
          .goAsync<OAuthConfigurationResponse>();
    }
		
    /// <summary>
    /// Retrieves the Oauth2 configuration for the application for the given Application Id.
    /// </summary>
    /// <param name="applicationId"> The Id of the Application to retrieve OAuth configuration.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<OAuthConfigurationResponse> RetrieveOauthConfiguration(Guid? applicationId) {
      return RetrieveOauthConfigurationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Returns the well known OpenID Configuration JSON document
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<OpenIdConfiguration>> RetrieveOpenIdConfigurationAsync() {
      return buildAnonymousClient()
          .withUri("/.well-known/openid-configuration")
          .withMethod("Get")
          .goAsync<OpenIdConfiguration>();
    }
		
    /// <summary>
    /// Returns the well known OpenID Configuration JSON document
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<OpenIdConfiguration> RetrieveOpenIdConfiguration() {
      return RetrieveOpenIdConfigurationAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided 
    /// through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
    /// 
    /// This API does not require an API key.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<PasswordValidationRulesResponse>> RetrievePasswordValidationRulesAsync() {
      return buildAnonymousClient()
          .withUri("/api/tenant/password-validation-rules")
          .withMethod("Get")
          .goAsync<PasswordValidationRulesResponse>();
    }
		
    /// <summary>
    /// Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided 
    /// through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
    /// 
    /// This API does not require an API key.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<PasswordValidationRulesResponse> RetrievePasswordValidationRules() {
      return RetrievePasswordValidationRulesAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the password validation rules for a specific tenant.
    /// 
    /// This API does not require an API key.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<PasswordValidationRulesResponse>> RetrievePasswordValidationRulesWithTenantIdAsync(Guid? tenantId) {
      return buildAnonymousClient()
          .withUri("/api/tenant/password-validation-rules")
          .withUriSegment(tenantId)
          .withMethod("Get")
          .goAsync<PasswordValidationRulesResponse>();
    }
		
    /// <summary>
    /// Retrieves the password validation rules for a specific tenant.
    /// 
    /// This API does not require an API key.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<PasswordValidationRulesResponse> RetrievePasswordValidationRulesWithTenantId(Guid? tenantId) {
      return RetrievePasswordValidationRulesWithTenantIdAsync(tenantId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the children for the given parent email address.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="parentEmail"> The email of the parent.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<PendingResponse>> RetrievePendingChildrenAsync(string parentEmail) {
      return buildClient()
          .withUri("/api/user/family/pending")
          .withParameter("parentEmail", parentEmail)
          .withMethod("Get")
          .goAsync<PendingResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the children for the given parent email address.
    /// </summary>
    /// <param name="parentEmail"> The email of the parent.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<PendingResponse> RetrievePendingChildren(string parentEmail) {
      return RetrievePendingChildrenAsync(parentEmail).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the last number of login records.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="offset"> The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.</param>
    /// <param name="limit"> (Optional, defaults to 10) The number of records to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RecentLoginResponse>> RetrieveRecentLoginsAsync(int? offset, int? limit) {
      return buildClient()
          .withUri("/api/user/recent-login")
          .withParameter("offset", offset)
          .withParameter("limit", limit)
          .withMethod("Get")
          .goAsync<RecentLoginResponse>();
    }
		
    /// <summary>
    /// Retrieves the last number of login records.
    /// </summary>
    /// <param name="offset"> The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.</param>
    /// <param name="limit"> (Optional, defaults to 10) The number of records to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RecentLoginResponse> RetrieveRecentLogins(int? offset, int? limit) {
      return RetrieveRecentLoginsAsync(offset, limit).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the refresh tokens that belong to the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RefreshResponse>> RetrieveRefreshTokensAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<RefreshResponse>();
    }
		
    /// <summary>
    /// Retrieves the refresh tokens that belong to the user with the given Id.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RefreshResponse> RetrieveRefreshTokens(Guid? userId) {
      return RetrieveRefreshTokensAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user registration for the user with the given id and the given application id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <param name="applicationId"> The Id of the application.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RegistrationResponse>> RetrieveRegistrationAsync(Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withUriSegment(applicationId)
          .withMethod("Get")
          .goAsync<RegistrationResponse>();
    }
		
    /// <summary>
    /// Retrieves the user registration for the user with the given id and the given application id.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <param name="applicationId"> The Id of the application.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RegistrationResponse> RetrieveRegistration(Guid? userId, Guid? applicationId) {
      return RetrieveRegistrationAsync(userId, applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the registration report between the two instants. If you specify an application id, it will only return
    /// the registration counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RegistrationReportResponse>> RetrieveRegistrationReportAsync(Guid? applicationId, long? start, long? end) {
      return buildClient()
          .withUri("/api/report/registration")
          .withParameter("applicationId", applicationId)
          .withParameter("start", start)
          .withParameter("end", end)
          .withMethod("Get")
          .goAsync<RegistrationReportResponse>();
    }
		
    /// <summary>
    /// Retrieves the registration report between the two instants. If you specify an application id, it will only return
    /// the registration counts for that application.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RegistrationReportResponse> RetrieveRegistrationReport(Guid? applicationId, long? start, long? end) {
      return RetrieveRegistrationReportAsync(applicationId, start, end).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the system configuration.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<SystemConfigurationResponse>> RetrieveSystemConfigurationAsync() {
      return buildClient()
          .withUri("/api/system-configuration")
          .withMethod("Get")
          .goAsync<SystemConfigurationResponse>();
    }
		
    /// <summary>
    /// Retrieves the system configuration.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<SystemConfigurationResponse> RetrieveSystemConfiguration() {
      return RetrieveSystemConfigurationAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the tenant for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<TenantResponse>> RetrieveTenantAsync(Guid? tenantId) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withMethod("Get")
          .goAsync<TenantResponse>();
    }
		
    /// <summary>
    /// Retrieves the tenant for the given Id.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<TenantResponse> RetrieveTenant(Guid? tenantId) {
      return RetrieveTenantAsync(tenantId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the tenants.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<TenantResponse>> RetrieveTenantsAsync() {
      return buildClient()
          .withUri("/api/tenant")
          .withMethod("Get")
          .goAsync<TenantResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the tenants.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<TenantResponse> RetrieveTenants() {
      return RetrieveTenantsAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the theme for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> The Id of the theme.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ThemeResponse>> RetrieveThemeAsync(Guid? themeId) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withMethod("Get")
          .goAsync<ThemeResponse>();
    }
		
    /// <summary>
    /// Retrieves the theme for the given Id.
    /// </summary>
    /// <param name="themeId"> The Id of the theme.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ThemeResponse> RetrieveTheme(Guid? themeId) {
      return RetrieveThemeAsync(themeId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the themes.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ThemeResponse>> RetrieveThemesAsync() {
      return buildClient()
          .withUri("/api/theme")
          .withMethod("Get")
          .goAsync<ThemeResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the themes.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ThemeResponse> RetrieveThemes() {
      return RetrieveThemesAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the totals report. This contains all of the total counts for each application and the global registration
    /// count.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<TotalsReportResponse>> RetrieveTotalReportAsync() {
      return buildClient()
          .withUri("/api/report/totals")
          .withMethod("Get")
          .goAsync<TotalsReportResponse>();
    }
		
    /// <summary>
    /// Retrieves the totals report. This contains all of the total counts for each application and the global registration
    /// count.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<TotalsReportResponse> RetrieveTotalReport() {
      return RetrieveTotalReportAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> RetrieveUserAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Retrieves the user for the given Id.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> RetrieveUser(Guid? userId) {
      return RetrieveUserAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user action for the given Id. If you pass in null for the id, this will return all of the user
    /// actions.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> (Optional) The Id of the user action.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionResponse>> RetrieveUserActionAsync(Guid? userActionId) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withMethod("Get")
          .goAsync<UserActionResponse>();
    }
		
    /// <summary>
    /// Retrieves the user action for the given Id. If you pass in null for the id, this will return all of the user
    /// actions.
    /// </summary>
    /// <param name="userActionId"> (Optional) The Id of the user action.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionResponse> RetrieveUserAction(Guid? userActionId) {
      return RetrieveUserActionAsync(userActionId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all of the user
    /// action reasons.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> (Optional) The Id of the user action reason.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionReasonResponse>> RetrieveUserActionReasonAsync(Guid? userActionReasonId) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withMethod("Get")
          .goAsync<UserActionReasonResponse>();
    }
		
    /// <summary>
    /// Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all of the user
    /// action reasons.
    /// </summary>
    /// <param name="userActionReasonId"> (Optional) The Id of the user action reason.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionReasonResponse> RetrieveUserActionReason(Guid? userActionReasonId) {
      return RetrieveUserActionReasonAsync(userActionReasonId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all the user action reasons.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionReasonResponse>> RetrieveUserActionReasonsAsync() {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withMethod("Get")
          .goAsync<UserActionReasonResponse>();
    }
		
    /// <summary>
    /// Retrieves all the user action reasons.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionReasonResponse> RetrieveUserActionReasons() {
      return RetrieveUserActionReasonsAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the user actions.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionResponse>> RetrieveUserActionsAsync() {
      return buildClient()
          .withUri("/api/user-action")
          .withMethod("Get")
          .goAsync<UserActionResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the user actions.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionResponse> RetrieveUserActions() {
      return RetrieveUserActionsAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
    /// password workflow has been initiated and you may not know the user's email or username.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="changePasswordId"> The unique change password Id that was sent via email or returned by the Forgot Password API.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> RetrieveUserByChangePasswordIdAsync(string changePasswordId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("changePasswordId", changePasswordId)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
    /// password workflow has been initiated and you may not know the user's email or username.
    /// </summary>
    /// <param name="changePasswordId"> The unique change password Id that was sent via email or returned by the Forgot Password API.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> RetrieveUserByChangePasswordId(string changePasswordId) {
      return RetrieveUserByChangePasswordIdAsync(changePasswordId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user for the given email.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> RetrieveUserByEmailAsync(string email) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("email", email)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Retrieves the user for the given email.
    /// </summary>
    /// <param name="email"> The email of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> RetrieveUserByEmail(string email) {
      return RetrieveUserByEmailAsync(email).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user for the loginId. The loginId can be either the username or the email.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="loginId"> The email or username of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> RetrieveUserByLoginIdAsync(string loginId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("loginId", loginId)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Retrieves the user for the loginId. The loginId can be either the username or the email.
    /// </summary>
    /// <param name="loginId"> The email or username of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> RetrieveUserByLoginId(string loginId) {
      return RetrieveUserByLoginIdAsync(loginId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user for the given username.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="username"> The username of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> RetrieveUserByUsernameAsync(string username) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("username", username)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Retrieves the user for the given username.
    /// </summary>
    /// <param name="username"> The username of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> RetrieveUserByUsername(string username) {
      return RetrieveUserByUsernameAsync(username).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
    /// password workflow has been initiated and you may not know the user's email or username.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="verificationId"> The unique verification Id that has been set on the user object.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> RetrieveUserByVerificationIdAsync(string verificationId) {
      return buildClient()
          .withUri("/api/user")
          .withParameter("verificationId", verificationId)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
    /// password workflow has been initiated and you may not know the user's email or username.
    /// </summary>
    /// <param name="verificationId"> The unique verification Id that has been set on the user object.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> RetrieveUserByVerificationId(string verificationId) {
      return RetrieveUserByVerificationIdAsync(verificationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the comments for the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserCommentResponse>> RetrieveUserCommentsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/comment")
          .withUriSegment(userId)
          .withMethod("Get")
          .goAsync<UserCommentResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the comments for the user with the given Id.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserCommentResponse> RetrieveUserComments(Guid? userId) {
      return RetrieveUserCommentsAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieve a single User consent by Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> The User consent Id</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserConsentResponse>> RetrieveUserConsentAsync(Guid? userConsentId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withMethod("Get")
          .goAsync<UserConsentResponse>();
    }
		
    /// <summary>
    /// Retrieve a single User consent by Id.
    /// </summary>
    /// <param name="userConsentId"> The User consent Id</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserConsentResponse> RetrieveUserConsent(Guid? userConsentId) {
      return RetrieveUserConsentAsync(userConsentId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all of the consents for a User.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The User's Id</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserConsentResponse>> RetrieveUserConsentsAsync(Guid? userId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withParameter("userId", userId)
          .withMethod("Get")
          .goAsync<UserConsentResponse>();
    }
		
    /// <summary>
    /// Retrieves all of the consents for a User.
    /// </summary>
    /// <param name="userId"> The User's Id</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserConsentResponse> RetrieveUserConsents(Guid? userId) {
      return RetrieveUserConsentsAsync(userId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
    /// login counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="userId"> The userId id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
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
		
    /// <summary>
    /// Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
    /// login counts for that application.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="userId"> The userId id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginReportResponse> RetrieveUserLoginReport(Guid? applicationId, Guid? userId, long? start, long? end) {
      return RetrieveUserLoginReportAsync(applicationId, userId, start, end).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
    /// login counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="loginId"> The userId id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
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
		
    /// <summary>
    /// Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
    /// login counts for that application.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="loginId"> The userId id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginReportResponse> RetrieveUserLoginReportByLoginId(Guid? applicationId, string loginId, long? start, long? end) {
      return RetrieveUserLoginReportByLoginIdAsync(applicationId, loginId, start, end).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the last number of login records for a user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <param name="offset"> The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.</param>
    /// <param name="limit"> (Optional, defaults to 10) The number of records to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RecentLoginResponse>> RetrieveUserRecentLoginsAsync(Guid? userId, int? offset, int? limit) {
      return buildClient()
          .withUri("/api/user/recent-login")
          .withParameter("userId", userId)
          .withParameter("offset", offset)
          .withParameter("limit", limit)
          .withMethod("Get")
          .goAsync<RecentLoginResponse>();
    }
		
    /// <summary>
    /// Retrieves the last number of login records for a user.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <param name="offset"> The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.</param>
    /// <param name="limit"> (Optional, defaults to 10) The number of records to retrieve.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RecentLoginResponse> RetrieveUserRecentLogins(Guid? userId, int? offset, int? limit) {
      return RetrieveUserRecentLoginsAsync(userId, offset, limit).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> RetrieveUserUsingJWTAsync(string encodedJWT) {
      return buildAnonymousClient()
          .withUri("/api/user")
          .withAuthorization("JWT " + encodedJWT)
          .withMethod("Get")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> RetrieveUserUsingJWT(string encodedJWT) {
      return RetrieveUserUsingJWTAsync(encodedJWT).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="webhookId"> (Optional) The Id of the webhook.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<WebhookResponse>> RetrieveWebhookAsync(Guid? webhookId) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withMethod("Get")
          .goAsync<WebhookResponse>();
    }
		
    /// <summary>
    /// Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
    /// </summary>
    /// <param name="webhookId"> (Optional) The Id of the webhook.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<WebhookResponse> RetrieveWebhook(Guid? webhookId) {
      return RetrieveWebhookAsync(webhookId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves all the webhooks.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<WebhookResponse>> RetrieveWebhooksAsync() {
      return buildClient()
          .withUri("/api/webhook")
          .withMethod("Get")
          .goAsync<WebhookResponse>();
    }
		
    /// <summary>
    /// Retrieves all the webhooks.
    /// </summary>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<WebhookResponse> RetrieveWebhooks() {
      return RetrieveWebhooksAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Revokes a single refresh token, all tokens for a user or all tokens for an application. If you provide a user id
    /// and an application id, this will delete all the refresh tokens for that user for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="token"> (Optional) The refresh token to delete.</param>
    /// <param name="userId"> (Optional) The user id whose tokens to delete.</param>
    /// <param name="applicationId"> (Optional) The application id of the tokens to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> RevokeRefreshTokenAsync(string token, Guid? userId, Guid? applicationId) {
      return buildClient()
          .withUri("/api/jwt/refresh")
          .withParameter("token", token)
          .withParameter("userId", userId)
          .withParameter("applicationId", applicationId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Revokes a single refresh token, all tokens for a user or all tokens for an application. If you provide a user id
    /// and an application id, this will delete all the refresh tokens for that user for that application.
    /// </summary>
    /// <param name="token"> (Optional) The refresh token to delete.</param>
    /// <param name="userId"> (Optional) The user id whose tokens to delete.</param>
    /// <param name="applicationId"> (Optional) The application id of the tokens to delete.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> RevokeRefreshToken(string token, Guid? userId, Guid? applicationId) {
      return RevokeRefreshTokenAsync(token, userId, applicationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Revokes a single User consent by Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> RevokeUserConsentAsync(Guid? userConsentId) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withMethod("Delete")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Revokes a single User consent by Id.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> RevokeUserConsent(Guid? userConsentId) {
      return RevokeUserConsentAsync(userConsentId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Searches the audit logs with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<AuditLogSearchResponse>> SearchAuditLogsAsync(AuditLogSearchRequest request) {
      return buildClient()
          .withUri("/api/system/audit-log/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<AuditLogSearchResponse>();
    }
		
    /// <summary>
    /// Searches the audit logs with the specified criteria and pagination.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<AuditLogSearchResponse> SearchAuditLogs(AuditLogSearchRequest request) {
      return SearchAuditLogsAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Searches the event logs with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<EventLogSearchResponse>> SearchEventLogsAsync(EventLogSearchRequest request) {
      return buildClient()
          .withUri("/api/system/event-log/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<EventLogSearchResponse>();
    }
		
    /// <summary>
    /// Searches the event logs with the specified criteria and pagination.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<EventLogSearchResponse> SearchEventLogs(EventLogSearchRequest request) {
      return SearchEventLogsAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Searches the login records with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LoginRecordSearchResponse>> SearchLoginRecordsAsync(LoginRecordSearchRequest request) {
      return buildClient()
          .withUri("/api/system/login-record/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginRecordSearchResponse>();
    }
		
    /// <summary>
    /// Searches the login records with the specified criteria and pagination.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginRecordSearchResponse> SearchLoginRecords(LoginRecordSearchRequest request) {
      return SearchLoginRecordsAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the users for the given ids. If any id is invalid, it is ignored.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="ids"> The user ids to search for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    [Obsolete("This method has been renamed to SearchUsersByIdsAsync, use that method instead.")]
    public Task<ClientResponse<SearchResponse>> SearchUsersAsync(List<string> ids) {
      return buildClient()
          .withUri("/api/user/search")
          .withParameter("ids", ids)
          .withMethod("Get")
          .goAsync<SearchResponse>();
    }
		
    /// <summary>
    /// Retrieves the users for the given ids. If any id is invalid, it is ignored.
    /// </summary>
    /// <param name="ids"> The user ids to search for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    [Obsolete("This method has been renamed to SearchUsersByIds, use that method instead.")]
    public ClientResponse<SearchResponse> SearchUsers(List<string> ids) {
      return SearchUsersAsync(ids).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the users for the given ids. If any id is invalid, it is ignored.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="ids"> The user ids to search for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<SearchResponse>> SearchUsersByIdsAsync(List<string> ids) {
      return buildClient()
          .withUri("/api/user/search")
          .withParameter("ids", ids)
          .withMethod("Get")
          .goAsync<SearchResponse>();
    }
		
    /// <summary>
    /// Retrieves the users for the given ids. If any id is invalid, it is ignored.
    /// </summary>
    /// <param name="ids"> The user ids to search for.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<SearchResponse> SearchUsersByIds(List<string> ids) {
      return SearchUsersByIdsAsync(ids).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the users for the given search criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
    /// and sortFields.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<SearchResponse>> SearchUsersByQueryAsync(SearchRequest request) {
      return buildClient()
          .withUri("/api/user/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<SearchResponse>();
    }
		
    /// <summary>
    /// Retrieves the users for the given search criteria and pagination.
    /// </summary>
    /// <param name="request"> The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
     /// and sortFields.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<SearchResponse> SearchUsersByQuery(SearchRequest request) {
      return SearchUsersByQueryAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Retrieves the users for the given search criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
    /// and sortFields.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    [Obsolete("This method has been renamed to SearchUsersByQueryAsync, use that method instead.")]
    public Task<ClientResponse<SearchResponse>> SearchUsersByQueryStringAsync(SearchRequest request) {
      return buildClient()
          .withUri("/api/user/search")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<SearchResponse>();
    }
		
    /// <summary>
    /// Retrieves the users for the given search criteria and pagination.
    /// </summary>
    /// <param name="request"> The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
     /// and sortFields.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    [Obsolete("This method has been renamed to SearchUsersByQuery, use that method instead.")]
    public ClientResponse<SearchResponse> SearchUsersByQueryString(SearchRequest request) {
      return SearchUsersByQueryStringAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
    /// pairs in the email template.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> The id for the template.</param>
    /// <param name="request"> The send email request that contains all of the information used to send the email.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<SendResponse>> SendEmailAsync(Guid? emailTemplateId, SendRequest request) {
      return buildClient()
          .withUri("/api/email/send")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<SendResponse>();
    }
		
    /// <summary>
    /// Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
    /// pairs in the email template.
    /// </summary>
    /// <param name="emailTemplateId"> The id for the template.</param>
    /// <param name="request"> The send email request that contains all of the information used to send the email.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<SendResponse> SendEmail(Guid? emailTemplateId, SendRequest request) {
      return SendEmailAsync(emailTemplateId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains the parent email.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> SendFamilyRequestEmailAsync(FamilyEmailRequest request) {
      return buildClient()
          .withUri("/api/user/family/request")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
    /// </summary>
    /// <param name="request"> The request object that contains the parent email.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> SendFamilyRequestEmail(FamilyEmailRequest request) {
      return SendFamilyRequestEmailAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Send a passwordless authentication code in an email to complete login.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The passwordless send request that contains all of the information used to send an email containing a code.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> SendPasswordlessCodeAsync(PasswordlessSendRequest request) {
      return buildAnonymousClient()
          .withUri("/api/passwordless/send")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Send a passwordless authentication code in an email to complete login.
    /// </summary>
    /// <param name="request"> The passwordless send request that contains all of the information used to send an email containing a code.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> SendPasswordlessCode(PasswordlessSendRequest request) {
      return SendPasswordlessCodeAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all of the information used to send the code.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> SendTwoFactorCodeAsync(TwoFactorSendRequest request) {
      return buildClient()
          .withUri("/api/two-factor/send")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
    /// </summary>
    /// <param name="request"> The request object that contains all of the information used to send the code.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> SendTwoFactorCode(TwoFactorSendRequest request) {
      return SendTwoFactorCodeAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="twoFactorId"> The Id returned by the Login API necessary to complete Two Factor authentication.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> SendTwoFactorCodeForLoginAsync(string twoFactorId) {
      return buildAnonymousClient()
          .withUri("/api/two-factor/send")
          .withUriSegment(twoFactorId)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
    /// </summary>
    /// <param name="twoFactorId"> The Id returned by the Login API necessary to complete Two Factor authentication.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> SendTwoFactorCodeForLogin(string twoFactorId) {
      return SendTwoFactorCodeForLoginAsync(twoFactorId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Begins a login request for a 3rd party login that requires user interaction such as HYPR.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The third-party login request that contains information from the third-party login
    /// providers that FusionAuth uses to reconcile the user's account.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IdentityProviderStartLoginResponse>> StartIdentityProviderLoginAsync(IdentityProviderStartLoginRequest request) {
      return buildClient()
          .withUri("/api/identity-provider/start")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<IdentityProviderStartLoginResponse>();
    }
		
    /// <summary>
    /// Begins a login request for a 3rd party login that requires user interaction such as HYPR.
    /// </summary>
    /// <param name="request"> The third-party login request that contains information from the third-party login
     /// providers that FusionAuth uses to reconcile the user's account.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IdentityProviderStartLoginResponse> StartIdentityProviderLogin(IdentityProviderStartLoginRequest request) {
      return StartIdentityProviderLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
    /// Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The passwordless start request that contains all of the information used to begin the passwordless login request.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<PasswordlessStartResponse>> StartPasswordlessLoginAsync(PasswordlessStartRequest request) {
      return buildClient()
          .withUri("/api/passwordless/start")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<PasswordlessStartResponse>();
    }
		
    /// <summary>
    /// Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
    /// Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
    /// </summary>
    /// <param name="request"> The passwordless start request that contains all of the information used to begin the passwordless login request.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<PasswordlessStartResponse> StartPasswordlessLogin(PasswordlessStartRequest request) {
      return StartPasswordlessLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Complete login using a 2FA challenge
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LoginResponse>> TwoFactorLoginAsync(TwoFactorLoginRequest request) {
      return buildAnonymousClient()
          .withUri("/api/two-factor/login")
          .withJSONBody(request)
          .withMethod("Post")
          .goAsync<LoginResponse>();
    }
		
    /// <summary>
    /// Complete login using a 2FA challenge
    /// </summary>
    /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LoginResponse> TwoFactorLogin(TwoFactorLoginRequest request) {
      return TwoFactorLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the application with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to update.</param>
    /// <param name="request"> The request that contains all of the new application information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ApplicationResponse>> UpdateApplicationAsync(Guid? applicationId, ApplicationRequest request) {
      return buildClient()
          .withUri("/api/application")
          .withUriSegment(applicationId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ApplicationResponse>();
    }
		
    /// <summary>
    /// Updates the application with the given Id.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to update.</param>
    /// <param name="request"> The request that contains all of the new application information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> UpdateApplication(Guid? applicationId, ApplicationRequest request) {
      return UpdateApplicationAsync(applicationId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the application role with the given id for the application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
    /// <param name="roleId"> The Id of the role to update.</param>
    /// <param name="request"> The request that contains all of the new role information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
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
		
    /// <summary>
    /// Updates the application role with the given id for the application.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
    /// <param name="roleId"> The Id of the role to update.</param>
    /// <param name="request"> The request that contains all of the new role information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ApplicationResponse> UpdateApplicationRole(Guid? applicationId, Guid? roleId, ApplicationRequest request) {
      return UpdateApplicationRoleAsync(applicationId, roleId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the consent with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to update.</param>
    /// <param name="request"> The request that contains all of the new consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ConsentResponse>> UpdateConsentAsync(Guid? consentId, ConsentRequest request) {
      return buildClient()
          .withUri("/api/consent")
          .withUriSegment(consentId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ConsentResponse>();
    }
		
    /// <summary>
    /// Updates the consent with the given Id.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to update.</param>
    /// <param name="request"> The request that contains all of the new consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ConsentResponse> UpdateConsent(Guid? consentId, ConsentRequest request) {
      return UpdateConsentAsync(consentId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the email template with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to update.</param>
    /// <param name="request"> The request that contains all of the new email template information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<EmailTemplateResponse>> UpdateEmailTemplateAsync(Guid? emailTemplateId, EmailTemplateRequest request) {
      return buildClient()
          .withUri("/api/email/template")
          .withUriSegment(emailTemplateId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<EmailTemplateResponse>();
    }
		
    /// <summary>
    /// Updates the email template with the given Id.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to update.</param>
    /// <param name="request"> The request that contains all of the new email template information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<EmailTemplateResponse> UpdateEmailTemplate(Guid? emailTemplateId, EmailTemplateRequest request) {
      return UpdateEmailTemplateAsync(emailTemplateId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the group with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> The Id of the group to update.</param>
    /// <param name="request"> The request that contains all of the new group information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<GroupResponse>> UpdateGroupAsync(Guid? groupId, GroupRequest request) {
      return buildClient()
          .withUri("/api/group")
          .withUriSegment(groupId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<GroupResponse>();
    }
		
    /// <summary>
    /// Updates the group with the given Id.
    /// </summary>
    /// <param name="groupId"> The Id of the group to update.</param>
    /// <param name="request"> The request that contains all of the new group information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<GroupResponse> UpdateGroup(Guid? groupId, GroupRequest request) {
      return UpdateGroupAsync(groupId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the identity provider with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to update.</param>
    /// <param name="request"> The request object that contains the updated identity provider.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IdentityProviderResponse>> UpdateIdentityProviderAsync(Guid? identityProviderId, IdentityProviderRequest request) {
      return buildClient()
          .withUri("/api/identity-provider")
          .withUriSegment(identityProviderId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<IdentityProviderResponse>();
    }
		
    /// <summary>
    /// Updates the identity provider with the given Id.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to update.</param>
    /// <param name="request"> The request object that contains the updated identity provider.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IdentityProviderResponse> UpdateIdentityProvider(Guid? identityProviderId, IdentityProviderRequest request) {
      return UpdateIdentityProviderAsync(identityProviderId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the available integrations.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains all of the new integration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<IntegrationResponse>> UpdateIntegrationsAsync(IntegrationRequest request) {
      return buildClient()
          .withUri("/api/integration")
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<IntegrationResponse>();
    }
		
    /// <summary>
    /// Updates the available integrations.
    /// </summary>
    /// <param name="request"> The request that contains all of the new integration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<IntegrationResponse> UpdateIntegrations(IntegrationRequest request) {
      return UpdateIntegrationsAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the key with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the key to update.</param>
    /// <param name="request"> The request that contains all of the new key information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<KeyResponse>> UpdateKeyAsync(Guid? keyId, KeyRequest request) {
      return buildClient()
          .withUri("/api/key")
          .withUriSegment(keyId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<KeyResponse>();
    }
		
    /// <summary>
    /// Updates the key with the given Id.
    /// </summary>
    /// <param name="keyId"> The Id of the key to update.</param>
    /// <param name="request"> The request that contains all of the new key information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<KeyResponse> UpdateKey(Guid? keyId, KeyRequest request) {
      return UpdateKeyAsync(keyId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the lambda with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to update.</param>
    /// <param name="request"> The request that contains all of the new lambda information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<LambdaResponse>> UpdateLambdaAsync(Guid? lambdaId, LambdaRequest request) {
      return buildClient()
          .withUri("/api/lambda")
          .withUriSegment(lambdaId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<LambdaResponse>();
    }
		
    /// <summary>
    /// Updates the lambda with the given Id.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to update.</param>
    /// <param name="request"> The request that contains all of the new lambda information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<LambdaResponse> UpdateLambda(Guid? lambdaId, LambdaRequest request) {
      return UpdateLambdaAsync(lambdaId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the registration for the user with the given id and the application defined in the request.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is going to be updated.</param>
    /// <param name="request"> The request that contains all of the new registration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RegistrationResponse>> UpdateRegistrationAsync(Guid? userId, RegistrationRequest request) {
      return buildClient()
          .withUri("/api/user/registration")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<RegistrationResponse>();
    }
		
    /// <summary>
    /// Updates the registration for the user with the given id and the application defined in the request.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is going to be updated.</param>
    /// <param name="request"> The request that contains all of the new registration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RegistrationResponse> UpdateRegistration(Guid? userId, RegistrationRequest request) {
      return UpdateRegistrationAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the system configuration.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains all of the new system configuration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<SystemConfigurationResponse>> UpdateSystemConfigurationAsync(SystemConfigurationRequest request) {
      return buildClient()
          .withUri("/api/system-configuration")
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<SystemConfigurationResponse>();
    }
		
    /// <summary>
    /// Updates the system configuration.
    /// </summary>
    /// <param name="request"> The request that contains all of the new system configuration information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<SystemConfigurationResponse> UpdateSystemConfiguration(SystemConfigurationRequest request) {
      return UpdateSystemConfigurationAsync(request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the tenant with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to update.</param>
    /// <param name="request"> The request that contains all of the new tenant information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<TenantResponse>> UpdateTenantAsync(Guid? tenantId, TenantRequest request) {
      return buildClient()
          .withUri("/api/tenant")
          .withUriSegment(tenantId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<TenantResponse>();
    }
		
    /// <summary>
    /// Updates the tenant with the given Id.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to update.</param>
    /// <param name="request"> The request that contains all of the new tenant information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<TenantResponse> UpdateTenant(Guid? tenantId, TenantRequest request) {
      return UpdateTenantAsync(tenantId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the theme with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to update.</param>
    /// <param name="request"> The request that contains all of the new theme information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ThemeResponse>> UpdateThemeAsync(Guid? themeId, ThemeRequest request) {
      return buildClient()
          .withUri("/api/theme")
          .withUriSegment(themeId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<ThemeResponse>();
    }
		
    /// <summary>
    /// Updates the theme with the given Id.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to update.</param>
    /// <param name="request"> The request that contains all of the new theme information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ThemeResponse> UpdateTheme(Guid? themeId, ThemeRequest request) {
      return UpdateThemeAsync(themeId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to update.</param>
    /// <param name="request"> The request that contains all of the new user information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserResponse>> UpdateUserAsync(Guid? userId, UserRequest request) {
      return buildClient()
          .withUri("/api/user")
          .withUriSegment(userId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<UserResponse>();
    }
		
    /// <summary>
    /// Updates the user with the given Id.
    /// </summary>
    /// <param name="userId"> The Id of the user to update.</param>
    /// <param name="request"> The request that contains all of the new user information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserResponse> UpdateUser(Guid? userId, UserRequest request) {
      return UpdateUserAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the user action with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to update.</param>
    /// <param name="request"> The request that contains all of the new user action information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionResponse>> UpdateUserActionAsync(Guid? userActionId, UserActionRequest request) {
      return buildClient()
          .withUri("/api/user-action")
          .withUriSegment(userActionId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<UserActionResponse>();
    }
		
    /// <summary>
    /// Updates the user action with the given Id.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to update.</param>
    /// <param name="request"> The request that contains all of the new user action information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionResponse> UpdateUserAction(Guid? userActionId, UserActionRequest request) {
      return UpdateUserActionAsync(userActionId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the user action reason with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to update.</param>
    /// <param name="request"> The request that contains all of the new user action reason information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserActionReasonResponse>> UpdateUserActionReasonAsync(Guid? userActionReasonId, UserActionReasonRequest request) {
      return buildClient()
          .withUri("/api/user-action-reason")
          .withUriSegment(userActionReasonId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<UserActionReasonResponse>();
    }
		
    /// <summary>
    /// Updates the user action reason with the given Id.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to update.</param>
    /// <param name="request"> The request that contains all of the new user action reason information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserActionReasonResponse> UpdateUserActionReason(Guid? userActionReasonId, UserActionReasonRequest request) {
      return UpdateUserActionReasonAsync(userActionReasonId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates a single User consent by Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <param name="request"> The request that contains the user consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<UserConsentResponse>> UpdateUserConsentAsync(Guid? userConsentId, UserConsentRequest request) {
      return buildClient()
          .withUri("/api/user/consent")
          .withUriSegment(userConsentId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<UserConsentResponse>();
    }
		
    /// <summary>
    /// Updates a single User consent by Id.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <param name="request"> The request that contains the user consent information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<UserConsentResponse> UpdateUserConsent(Guid? userConsentId, UserConsentRequest request) {
      return UpdateUserConsentAsync(userConsentId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Updates the webhook with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="webhookId"> The Id of the webhook to update.</param>
    /// <param name="request"> The request that contains all of the new webhook information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<WebhookResponse>> UpdateWebhookAsync(Guid? webhookId, WebhookRequest request) {
      return buildClient()
          .withUri("/api/webhook")
          .withUriSegment(webhookId)
          .withJSONBody(request)
          .withMethod("Put")
          .goAsync<WebhookResponse>();
    }
		
    /// <summary>
    /// Updates the webhook with the given Id.
    /// </summary>
    /// <param name="webhookId"> The Id of the webhook to update.</param>
    /// <param name="request"> The request that contains all of the new webhook information.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<WebhookResponse> UpdateWebhook(Guid? webhookId, WebhookRequest request) {
      return UpdateWebhookAsync(webhookId, request).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
    /// If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="user_code"> The end-user verification code.</param>
    /// <param name="client_id"> The client id.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> ValidateDeviceAsync(string user_code, string client_id) {
      return buildAnonymousClient()
          .withUri("/oauth2/device/validate")
          .withParameter("user_code", user_code)
          .withParameter("client_id", client_id)
          .withMethod("Get")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
    /// If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
    /// </summary>
    /// <param name="user_code"> The end-user verification code.</param>
    /// <param name="client_id"> The client id.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> ValidateDevice(string user_code, string client_id) {
      return ValidateDeviceAsync(user_code, client_id).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
    /// signed and not expired.
    /// <p>
    /// This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<ValidateResponse>> ValidateJWTAsync(string encodedJWT) {
      return buildAnonymousClient()
          .withUri("/api/jwt/validate")
          .withAuthorization("JWT " + encodedJWT)
          .withMethod("Get")
          .goAsync<ValidateResponse>();
    }
		
    /// <summary>
    /// Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
    /// signed and not expired.
    /// <p>
    /// This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<ValidateResponse> ValidateJWT(string encodedJWT) {
      return ValidateJWTAsync(encodedJWT).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Confirms a email verification. The Id given is usually from an email sent to the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="verificationId"> The email verification id sent to the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> VerifyEmailAsync(string verificationId) {
      return buildAnonymousClient()
          .withUri("/api/user/verify-email")
          .withUriSegment(verificationId)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Confirms a email verification. The Id given is usually from an email sent to the user.
    /// </summary>
    /// <param name="verificationId"> The email verification id sent to the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> VerifyEmail(string verificationId) {
      return VerifyEmailAsync(verificationId).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Confirms an application registration. The Id given is usually from an email sent to the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="verificationId"> The registration verification Id sent to the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public Task<ClientResponse<RESTVoid>> VerifyRegistrationAsync(string verificationId) {
      return buildAnonymousClient()
          .withUri("/api/user/verify-registration")
          .withUriSegment(verificationId)
          .withMethod("Post")
          .goAsync<RESTVoid>();
    }
		
    /// <summary>
    /// Confirms an application registration. The Id given is usually from an email sent to the user.
    /// </summary>
    /// <param name="verificationId"> The registration verification Id sent to the user.</param>
    /// <returns>When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.</returns>
    public ClientResponse<RESTVoid> VerifyRegistration(string verificationId) {
      return VerifyRegistrationAsync(verificationId).GetAwaiter().GetResult();
    }
  }

  internal class DefaultRESTClientBuilder : IRESTClientBuilder {
    public IRESTClient build(string host) {
      return new DefaultRESTClient(host);
    }
  }
}
