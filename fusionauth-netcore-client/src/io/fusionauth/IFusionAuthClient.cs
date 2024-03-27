/*
 * Copyright (c) 2020-2023, FusionAuth, All Rights Reserved
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
  public interface IFusionAuthAsyncClient {

    /// <summary>
    /// Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
    /// "actioner". Both user ids are required in the request object.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The action request that includes all the information about the action being taken including
    /// the Id of the action, any options and the duration (if applicable).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ActionResponse>> ActionUserAsync(ActionRequest request);

    /// <summary>
    /// Activates the FusionAuth Reactor using a license Id and optionally a license text (for air-gapped deployments)
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> An optional request that contains the license text to activate Reactor (useful for air-gap deployments of FusionAuth).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> ActivateReactorAsync(ReactorRequest request);

    /// <summary>
    /// Adds a user to an existing family. The family Id must be specified.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="familyId"> The Id of the family.</param>
    /// <param name="request"> The request object that contains all the information used to determine which user to add to the family.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FamilyResponse>> AddUserToFamilyAsync(Guid? familyId, FamilyRequest request);

    /// <summary>
    /// Approve a device grant.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value will be required if client authentication is enabled.</param>
    /// <param name="token"> The access token used to identify the user.</param>
    /// <param name="user_code"> The end-user verification code.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<DeviceApprovalResponse>> ApproveDeviceAsync(string client_id, string client_secret, string token, string user_code);

    /// <summary>
    /// Cancels the user action.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="actionId"> The action Id of the action to cancel.</param>
    /// <param name="request"> The action request that contains the information about the cancellation.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ActionResponse>> CancelActionAsync(Guid? actionId, ActionRequest request);

    /// <summary>
    /// Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
    /// and they clicked on a link to reset their password.
    /// 
    /// As of version 1.32.2, prefer sending the changePasswordId in the request body. To do this, omit the first parameter, and set
    /// the value in the request body.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="changePasswordId"> The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.</param>
    /// <param name="request"> The change password request that contains all the information used to change the password.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ChangePasswordResponse>> ChangePasswordAsync(string changePasswordId, ChangePasswordRequest request);

    /// <summary>
    /// Changes a user's password using their identity (loginId and password). Using a loginId instead of the changePasswordId
    /// bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
    /// method.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The change password request that contains all the information used to change the password.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> ChangePasswordByIdentityAsync(ChangePasswordRequest request);

    /// <summary>
    /// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
    /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
    /// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
    /// 
    /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="changePasswordId"> The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> CheckChangePasswordUsingIdAsync(string changePasswordId);

    /// <summary>
    /// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
    /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
    /// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
    /// 
    /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> CheckChangePasswordUsingJWTAsync(string encodedJWT);

    /// <summary>
    /// Check to see if the user must obtain a Trust Request Id in order to complete a change password request.
    /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
    /// your password, you must obtain a Trust Request Id by completing a Two-Factor Step-Up authentication.
    /// 
    /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="loginId"> The loginId of the User that you intend to change the password for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> CheckChangePasswordUsingLoginIdAsync(string loginId);

    /// <summary>
    /// Make a Client Credentials grant request to obtain an access token.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="client_id"> (Optional) The client identifier. The client Id is the Id of the FusionAuth Entity in which you are attempting to authenticate.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
    /// <param name="client_secret"> (Optional) The client secret used to authenticate this request.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
    /// <param name="scope"> (Optional) This parameter is used to indicate which target entity you are requesting access. To request access to an entity, use the format target-entity:&lt;target-entity-id&gt;:&lt;roles&gt;. Roles are an optional comma separated list.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<AccessToken>> ClientCredentialsGrantAsync(string client_id, string client_secret, string scope);

    /// <summary>
    /// Adds a comment to the user's account.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all the information used to create the user comment.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserCommentResponse>> CommentOnUserAsync(UserCommentRequest request);

    /// <summary>
    /// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge without logging the user in
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> An object containing data necessary for completing the authentication ceremony</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebAuthnAssertResponse>> CompleteWebAuthnAssertionAsync(WebAuthnLoginRequest request);

    /// <summary>
    /// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge and then login the user in
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> An object containing data necessary for completing the authentication ceremony</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginResponse>> CompleteWebAuthnLoginAsync(WebAuthnLoginRequest request);

    /// <summary>
    /// Complete a WebAuthn registration ceremony by validating the client request and saving the new credential
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> An object containing data necessary for completing the registration ceremony</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebAuthnRegisterCompleteResponse>> CompleteWebAuthnRegistrationAsync(WebAuthnRegisterCompleteRequest request);

    /// <summary>
    /// Creates an API key. You can optionally specify a unique Id for the key, if not provided one will be generated.
    /// an API key can only be created with equal or lesser authority. An API key cannot create another API key unless it is granted 
    /// to that API key.
    /// 
    /// If an API key is locked to a tenant, it can only create API Keys for that same tenant.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> (Optional) The unique Id of the API key. If not provided a secure random Id will be generated.</param>
    /// <param name="request"> The request object that contains all the information needed to create the APIKey.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<APIKeyResponse>> CreateAPIKeyAsync(Guid? keyId, APIKeyRequest request);

    /// <summary>
    /// Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the application.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> CreateApplicationAsync(Guid? applicationId, ApplicationRequest request);

    /// <summary>
    /// Creates a new role for an application. You must specify the Id of the application you are creating the role for.
    /// You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to create the role on.</param>
    /// <param name="roleId"> (Optional) The Id of the role. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the application role.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> CreateApplicationRoleAsync(Guid? applicationId, Guid? roleId, ApplicationRequest request);

    /// <summary>
    /// Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
    /// make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
    /// written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all the information used to create the audit log entry.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<AuditLogResponse>> CreateAuditLogAsync(AuditLogRequest request);

    /// <summary>
    /// Creates a connector.  You can optionally specify an Id for the connector, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="connectorId"> (Optional) The Id for the connector. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the connector.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConnectorResponse>> CreateConnectorAsync(Guid? connectorId, ConnectorRequest request);

    /// <summary>
    /// Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> (Optional) The Id for the consent. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the consent.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConsentResponse>> CreateConsentAsync(Guid? consentId, ConsentRequest request);

    /// <summary>
    /// Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> (Optional) The Id for the template. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the email template.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EmailTemplateResponse>> CreateEmailTemplateAsync(Guid? emailTemplateId, EmailTemplateRequest request);

    /// <summary>
    /// Creates an Entity. You can optionally specify an Id for the Entity. If not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityId"> (Optional) The Id for the Entity. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the Entity.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityResponse>> CreateEntityAsync(Guid? entityId, EntityRequest request);

    /// <summary>
    /// Creates a Entity Type. You can optionally specify an Id for the Entity Type, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityTypeId"> (Optional) The Id for the Entity Type. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the Entity Type.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityTypeResponse>> CreateEntityTypeAsync(Guid? entityTypeId, EntityTypeRequest request);

    /// <summary>
    /// Creates a new permission for an entity type. You must specify the Id of the entity type you are creating the permission for.
    /// You can optionally specify an Id for the permission inside the EntityTypePermission object itself, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityTypeId"> The Id of the entity type to create the permission on.</param>
    /// <param name="permissionId"> (Optional) The Id of the permission. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the permission.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityTypeResponse>> CreateEntityTypePermissionAsync(Guid? entityTypeId, Guid? permissionId, EntityTypeRequest request);

    /// <summary>
    /// Creates a family with the user Id in the request as the owner and sole member of the family. You can optionally specify an Id for the
    /// family, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="familyId"> (Optional) The Id for the family. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the family.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FamilyResponse>> CreateFamilyAsync(Guid? familyId, FamilyRequest request);

    /// <summary>
    /// Creates a form.  You can optionally specify an Id for the form, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="formId"> (Optional) The Id for the form. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the form.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FormResponse>> CreateFormAsync(Guid? formId, FormRequest request);

    /// <summary>
    /// Creates a form field.  You can optionally specify an Id for the form, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="fieldId"> (Optional) The Id for the form field. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the form field.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FormFieldResponse>> CreateFormFieldAsync(Guid? fieldId, FormFieldRequest request);

    /// <summary>
    /// Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> (Optional) The Id for the group. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the group.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<GroupResponse>> CreateGroupAsync(Guid? groupId, GroupRequest request);

    /// <summary>
    /// Creates a member in a group.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all the information used to create the group member(s).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MemberResponse>> CreateGroupMembersAsync(MemberRequest request);

    /// <summary>
    /// Creates an IP Access Control List. You can optionally specify an Id on this create request, if one is not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="accessControlListId"> (Optional) The Id for the IP Access Control List. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the IP Access Control List.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IPAccessControlListResponse>> CreateIPAccessControlListAsync(Guid? accessControlListId, IPAccessControlListRequest request);

    /// <summary>
    /// Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the identity provider.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderResponse>> CreateIdentityProviderAsync(Guid? identityProviderId, IdentityProviderRequest request);

    /// <summary>
    /// Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the lambda.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LambdaResponse>> CreateLambdaAsync(Guid? lambdaId, LambdaRequest request);

    /// <summary>
    /// Creates an message template. You can optionally specify an Id for the template, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messageTemplateId"> (Optional) The Id for the template. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the message template.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessageTemplateResponse>> CreateMessageTemplateAsync(Guid? messageTemplateId, MessageTemplateRequest request);

    /// <summary>
    /// Creates a messenger.  You can optionally specify an Id for the messenger, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messengerId"> (Optional) The Id for the messenger. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the messenger.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessengerResponse>> CreateMessengerAsync(Guid? messengerId, MessengerRequest request);

    /// <summary>
    /// Creates a new custom OAuth scope for an application. You must specify the Id of the application you are creating the scope for.
    /// You can optionally specify an Id for the OAuth scope on the URL, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to create the OAuth scope on.</param>
    /// <param name="scopeId"> (Optional) The Id of the OAuth scope. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the OAuth OAuth scope.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationOAuthScopeResponse>> CreateOAuthScopeAsync(Guid? applicationId, Guid? scopeId, ApplicationOAuthScopeRequest request);

    /// <summary>
    /// Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the tenant.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TenantResponse>> CreateTenantAsync(Guid? tenantId, TenantRequest request);

    /// <summary>
    /// Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> (Optional) The Id for the theme. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the theme.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ThemeResponse>> CreateThemeAsync(Guid? themeId, ThemeRequest request);

    /// <summary>
    /// Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> (Optional) The Id for the user. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> CreateUserAsync(Guid? userId, UserRequest request);

    /// <summary>
    /// Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
    /// that the user action can be applied to any user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> (Optional) The Id for the user action. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the user action.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionResponse>> CreateUserActionAsync(Guid? userActionId, UserActionRequest request);

    /// <summary>
    /// Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
    /// successfully. Anytime after that the user action reason can be used.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the user action reason.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionReasonResponse>> CreateUserActionReasonAsync(Guid? userActionReasonId, UserActionReasonRequest request);

    /// <summary>
    /// Creates a single User consent.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request that contains the user consent information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserConsentResponse>> CreateUserConsentAsync(Guid? userConsentId, UserConsentRequest request);

    /// <summary>
    /// Link an external user from a 3rd party identity provider to a FusionAuth user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all the information used to link the FusionAuth user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderLinkResponse>> CreateUserLinkAsync(IdentityProviderLinkRequest request);

    /// <summary>
    /// Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="webhookId"> (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the webhook.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebhookResponse>> CreateWebhookAsync(Guid? webhookId, WebhookRequest request);

    /// <summary>
    /// Deactivates the application with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to deactivate.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeactivateApplicationAsync(Guid? applicationId);

    /// <summary>
    /// Deactivates the FusionAuth Reactor.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeactivateReactorAsync();

    /// <summary>
    /// Deactivates the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to deactivate.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeactivateUserAsync(Guid? userId);

    /// <summary>
    /// Deactivates the user action with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to deactivate.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeactivateUserActionAsync(Guid? userActionId);

    /// <summary>
    /// Deactivates the users with the given ids.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userIds"> The ids of the users to deactivate.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    [Obsolete("This method has been renamed to DeactivateUsersByIdsAsync, use that method instead.")]
    Task<ClientResponse<UserDeleteResponse>> DeactivateUsersAsync(List<string> userIds);

    /// <summary>
    /// Deactivates the users with the given ids.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userIds"> The ids of the users to deactivate.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserDeleteResponse>> DeactivateUsersByIdsAsync(List<string> userIds);

    /// <summary>
    /// Deletes the API key for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the authentication API key to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteAPIKeyAsync(Guid? keyId);

    /// <summary>
    /// Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
    /// delete the application, any registrations for that application, metrics and reports for the application, all the
    /// roles for the application, and any other data associated with the application. This operation could take a very
    /// long time, depending on the amount of data in your database.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteApplicationAsync(Guid? applicationId);

    /// <summary>
    /// Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
    /// permanently removes the given role from all users that had it.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
    /// <param name="roleId"> The Id of the role to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteApplicationRoleAsync(Guid? applicationId, Guid? roleId);

    /// <summary>
    /// Deletes the connector for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="connectorId"> The Id of the connector to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteConnectorAsync(Guid? connectorId);

    /// <summary>
    /// Deletes the consent for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteConsentAsync(Guid? consentId);

    /// <summary>
    /// Deletes the email template for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteEmailTemplateAsync(Guid? emailTemplateId);

    /// <summary>
    /// Deletes the Entity for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityId"> The Id of the Entity to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteEntityAsync(Guid? entityId);

    /// <summary>
    /// Deletes an Entity Grant for the given User or Entity.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityId"> The Id of the Entity that the Entity Grant is being deleted for.</param>
    /// <param name="recipientEntityId"> (Optional) The Id of the Entity that the Entity Grant is for.</param>
    /// <param name="userId"> (Optional) The Id of the User that the Entity Grant is for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteEntityGrantAsync(Guid? entityId, Guid? recipientEntityId, Guid? userId);

    /// <summary>
    /// Deletes the Entity Type for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityTypeId"> The Id of the Entity Type to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteEntityTypeAsync(Guid? entityTypeId);

    /// <summary>
    /// Hard deletes a permission. This is a dangerous operation and should not be used in most circumstances. This
    /// permanently removes the given permission from all grants that had it.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityTypeId"> The Id of the entityType the the permission belongs to.</param>
    /// <param name="permissionId"> The Id of the permission to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteEntityTypePermissionAsync(Guid? entityTypeId, Guid? permissionId);

    /// <summary>
    /// Deletes the form for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="formId"> The Id of the form to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteFormAsync(Guid? formId);

    /// <summary>
    /// Deletes the form field for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="fieldId"> The Id of the form field to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteFormFieldAsync(Guid? fieldId);

    /// <summary>
    /// Deletes the group for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> The Id of the group to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteGroupAsync(Guid? groupId);

    /// <summary>
    /// Removes users as members of a group.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The member request that contains all the information used to remove members to the group.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteGroupMembersAsync(MemberDeleteRequest request);

    /// <summary>
    /// Deletes the IP Access Control List for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="ipAccessControlListId"> The Id of the IP Access Control List to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteIPAccessControlListAsync(Guid? ipAccessControlListId);

    /// <summary>
    /// Deletes the identity provider for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteIdentityProviderAsync(Guid? identityProviderId);

    /// <summary>
    /// Deletes the key for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the key to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteKeyAsync(Guid? keyId);

    /// <summary>
    /// Deletes the lambda for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteLambdaAsync(Guid? lambdaId);

    /// <summary>
    /// Deletes the message template for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messageTemplateId"> The Id of the message template to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteMessageTemplateAsync(Guid? messageTemplateId);

    /// <summary>
    /// Deletes the messenger for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messengerId"> The Id of the messenger to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteMessengerAsync(Guid? messengerId);

    /// <summary>
    /// Hard deletes a custom OAuth scope. This action will cause tokens that contain the deleted scope to be rejected.
    /// OAuth workflows that are still requesting the deleted OAuth scope may fail depending on the application's unknown scope policy.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the OAuth scope belongs to.</param>
    /// <param name="scopeId"> The Id of the OAuth scope to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteOAuthScopeAsync(Guid? applicationId, Guid? scopeId);

    /// <summary>
    /// Deletes the user registration for the given user and application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is being deleted.</param>
    /// <param name="applicationId"> The Id of the application to remove the registration for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteRegistrationAsync(Guid? userId, Guid? applicationId);

    /// <summary>
    /// Deletes the user registration for the given user and application along with the given JSON body that contains the event information.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is being deleted.</param>
    /// <param name="applicationId"> The Id of the application to remove the registration for.</param>
    /// <param name="request"> The request body that contains the event information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteRegistrationWithRequestAsync(Guid? userId, Guid? applicationId, RegistrationDeleteRequest request);

    /// <summary>
    /// Deletes the tenant based on the given Id on the URL. This permanently deletes all information, metrics, reports and data associated
    /// with the tenant and everything under the tenant (applications, users, etc).
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteTenantAsync(Guid? tenantId);

    /// <summary>
    /// Deletes the tenant for the given Id asynchronously.
    /// This method is helpful if you do not want to wait for the delete operation to complete.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteTenantAsyncAsync(Guid? tenantId);

    /// <summary>
    /// Deletes the tenant based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
    /// with the tenant and everything under the tenant (applications, users, etc).
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to delete.</param>
    /// <param name="request"> The request object that contains all the information used to delete the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteTenantWithRequestAsync(Guid? tenantId, TenantDeleteRequest request);

    /// <summary>
    /// Deletes the theme for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteThemeAsync(Guid? themeId);

    /// <summary>
    /// Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
    /// with the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteUserAsync(Guid? userId);

    /// <summary>
    /// Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
    /// the action being applied to any users.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteUserActionAsync(Guid? userActionId);

    /// <summary>
    /// Deletes the user action reason for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteUserActionReasonAsync(Guid? userActionReasonId);

    /// <summary>
    /// Remove an existing link that has been made from a 3rd party identity provider to a FusionAuth user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The unique Id of the identity provider.</param>
    /// <param name="identityProviderUserId"> The unique Id of the user in the 3rd party identity provider to unlink.</param>
    /// <param name="userId"> The unique Id of the FusionAuth user to unlink.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderLinkResponse>> DeleteUserLinkAsync(Guid? identityProviderId, string identityProviderUserId, Guid? userId);

    /// <summary>
    /// Deletes the user based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
    /// with the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to delete (required).</param>
    /// <param name="request"> The request object that contains all the information used to delete the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteUserWithRequestAsync(Guid? userId, UserDeleteSingleRequest request);

    /// <summary>
    /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
    /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
    /// 
    /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
    /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The UserDeleteRequest.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    [Obsolete("This method has been renamed to DeleteUsersByQueryAsync, use that method instead.")]
    Task<ClientResponse<UserDeleteResponse>> DeleteUsersAsync(UserDeleteRequest request);

    /// <summary>
    /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
    /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
    /// 
    /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
    /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The UserDeleteRequest.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserDeleteResponse>> DeleteUsersByQueryAsync(UserDeleteRequest request);

    /// <summary>
    /// Deletes the WebAuthn credential for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="id"> The Id of the WebAuthn credential to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteWebAuthnCredentialAsync(Guid? id);

    /// <summary>
    /// Deletes the webhook for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="webhookId"> The Id of the webhook to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DeleteWebhookAsync(Guid? webhookId);

    /// <summary>
    /// Disable two-factor authentication for a user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the User for which you're disabling two-factor authentication.</param>
    /// <param name="methodId"> The two-factor method identifier you wish to disable</param>
    /// <param name="code"> The two-factor code used verify the the caller knows the two-factor secret.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DisableTwoFactorAsync(Guid? userId, string methodId, string code);

    /// <summary>
    /// Disable two-factor authentication for a user using a JSON body rather than URL parameters.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the User for which you're disabling two-factor authentication.</param>
    /// <param name="request"> The request information that contains the code and methodId along with any event information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> DisableTwoFactorWithRequestAsync(Guid? userId, TwoFactorDisableRequest request);

    /// <summary>
    /// Enable two-factor authentication for a user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to enable two-factor authentication.</param>
    /// <param name="request"> The two-factor enable request information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TwoFactorResponse>> EnableTwoFactorAsync(Guid? userId, TwoFactorRequest request);

    /// <summary>
    /// Exchanges an OAuth authorization code for an access token.
    /// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="code"> The authorization code returned on the /oauth2/authorize response.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value will be required if client authentication is enabled.</param>
    /// <param name="redirect_uri"> The URI to redirect to upon a successful request.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<AccessToken>> ExchangeOAuthCodeForAccessTokenAsync(string code, string client_id, string client_secret, string redirect_uri);

    /// <summary>
    /// Exchanges an OAuth authorization code and code_verifier for an access token.
    /// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint and a code_verifier for an access token.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="code"> The authorization code returned on the /oauth2/authorize response.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="redirect_uri"> The URI to redirect to upon a successful request.</param>
    /// <param name="code_verifier"> The random string generated previously. Will be compared with the code_challenge sent previously, which allows the OAuth provider to authenticate your app.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<AccessToken>> ExchangeOAuthCodeForAccessTokenUsingPKCEAsync(string code, string client_id, string client_secret, string redirect_uri, string code_verifier);

    /// <summary>
    /// Exchange a Refresh Token for an Access Token.
    /// If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="refresh_token"> The refresh token that you would like to use to exchange for an access token.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="scope"> (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.</param>
    /// <param name="user_code"> (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<AccessToken>> ExchangeRefreshTokenForAccessTokenAsync(string refresh_token, string client_id, string client_secret, string scope, string user_code);

    /// <summary>
    /// Exchange a refresh token for a new JWT.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The refresh request.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<JWTRefreshResponse>> ExchangeRefreshTokenForJWTAsync(RefreshRequest request);

    /// <summary>
    /// Exchange User Credentials for a Token.
    /// If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="username"> The login identifier of the user. The login identifier can be either the email or the username.</param>
    /// <param name="password"> The user’s password.</param>
    /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
    /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
    /// <param name="scope"> (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.</param>
    /// <param name="user_code"> (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<AccessToken>> ExchangeUserCredentialsForAccessTokenAsync(string username, string password, string client_id, string client_secret, string scope, string user_code);

    /// <summary>
    /// Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the information about the user so that they can be emailed.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ForgotPasswordResponse>> ForgotPasswordAsync(ForgotPasswordRequest request);

    /// <summary>
    /// Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
    /// email to the User. This API may be used to collect the verificationId for use with a third party system.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<VerifyEmailResponse>> GenerateEmailVerificationIdAsync(string email);

    /// <summary>
    /// Generate a new RSA or EC key pair or an HMAC secret.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> (Optional) The Id for the key. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the key.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<KeyResponse>> GenerateKeyAsync(Guid? keyId, KeyRequest request);

    /// <summary>
    /// Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
    /// email to the User. This API may be used to collect the verificationId for use with a third party system.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <param name="applicationId"> The Id of the application to be verified.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<VerifyRegistrationResponse>> GenerateRegistrationVerificationIdAsync(string email, Guid? applicationId);

    /// <summary>
    /// Generate two-factor recovery codes for a user. Generating two-factor recovery codes will invalidate any existing recovery codes. 
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to generate new Two Factor recovery codes.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TwoFactorRecoveryCodeResponse>> GenerateTwoFactorRecoveryCodesAsync(Guid? userId);

    /// <summary>
    /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
    /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
    /// application such as Google Authenticator.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<SecretResponse>> GenerateTwoFactorSecretAsync();

    /// <summary>
    /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
    /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
    /// application such as Google Authenticator.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<SecretResponse>> GenerateTwoFactorSecretUsingJWTAsync(string encodedJWT);

    /// <summary>
    /// Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
    /// login systems.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The third-party login request that contains information from the third-party login
    /// providers that FusionAuth uses to reconcile the user's account.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginResponse>> IdentityProviderLoginAsync(IdentityProviderLoginRequest request);

    /// <summary>
    /// Import an existing RSA or EC key pair or an HMAC secret.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> (Optional) The Id for the key. If not provided a secure random UUID will be generated.</param>
    /// <param name="request"> The request object that contains all the information used to create the key.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<KeyResponse>> ImportKeyAsync(Guid? keyId, KeyRequest request);

    /// <summary>
    /// Bulk imports refresh tokens. This request performs minimal validation and runs batch inserts of refresh tokens with the
    /// expectation that each token represents a user that already exists and is registered for the corresponding FusionAuth
    /// Application. This is done to increases the insert performance.
    /// 
    /// Therefore, if you encounter an error due to a database key violation, the response will likely offer a generic
    /// explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
    /// body with specific validation errors. This will slow the request down but will allow you to identify the cause of
    /// the failure. See the validateDbConstraints request parameter.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains all the information about all the refresh tokens to import.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> ImportRefreshTokensAsync(RefreshTokenImportRequest request);

    /// <summary>
    /// Bulk imports users. This request performs minimal validation and runs batch inserts of users with the expectation
    /// that each user does not yet exist and each registration corresponds to an existing FusionAuth Application. This is done to
    /// increases the insert performance.
    /// 
    /// Therefore, if you encounter an error due to a database key violation, the response will likely offer
    /// a generic explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
    /// body with specific validation errors. This will slow the request down but will allow you to identify the cause of the failure. See
    /// the validateDbConstraints request parameter.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains all the information about all the users to import.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> ImportUsersAsync(ImportRequest request);

    /// <summary>
    /// Import a WebAuthn credential
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> An object containing data necessary for importing the credential</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> ImportWebAuthnCredentialAsync(WebAuthnCredentialImportRequest request);

    /// <summary>
    /// Inspect an access token issued as the result of the User based grant such as the Authorization Code Grant, Implicit Grant, the User Credentials Grant or the Refresh Grant.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="client_id"> The unique client identifier. The client Id is the Id of the FusionAuth Application for which this token was generated.</param>
    /// <param name="token"> The access token returned by this OAuth provider as the result of a successful client credentials grant.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IntrospectResponse>> IntrospectAccessTokenAsync(string client_id, string token);

    /// <summary>
    /// Inspect an access token issued as the result of the Client Credentials Grant.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="token"> The access token returned by this OAuth provider as the result of a successful client credentials grant.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IntrospectResponse>> IntrospectClientCredentialsAccessTokenAsync(string token);

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
    /// <param name="refreshToken"> (Optional) An existing refresh token used to request a refresh token in addition to a JWT in the response.
    /// <p>The target application represented by the applicationId request parameter must have refresh
    /// tokens enabled in order to receive a refresh token in the response.</p></param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IssueResponse>> IssueJWTAsync(Guid? applicationId, string encodedJWT, string refreshToken);

    /// <summary>
    /// Authenticates a user to FusionAuth. 
    /// 
    /// This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginResponse>> LoginAsync(LoginRequest request);

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
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginResponse>> LoginPingAsync(Guid? userId, Guid? applicationId, string callerIPAddress);

    /// <summary>
    /// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
    /// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
    /// application where they no longer have a session. This helps correctly track login counts, times and helps with
    /// reporting.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginResponse>> LoginPingWithRequestAsync(LoginPingRequest request);

    /// <summary>
    /// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
    /// client and revoke the refresh token stored. This API does nothing if the request does not contain an access
    /// token or refresh token cookies.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="global"> When this value is set to true all the refresh tokens issued to the owner of the
    /// provided token will be revoked.</param>
    /// <param name="refreshToken"> (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
    /// If provided this takes precedence over the cookie.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> LogoutAsync(bool? global, string refreshToken);

    /// <summary>
    /// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
    /// client and revoke the refresh token stored. This API takes the refresh token in the JSON body.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all the information used to logout the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> LogoutWithRequestAsync(LogoutRequest request);

    /// <summary>
    /// Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
    /// by a registered identity provider. A 404 indicates the domain is not managed.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="domain"> The domain or email address to lookup.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LookupResponse>> LookupIdentityProviderAsync(string domain);

    /// <summary>
    /// Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
    /// action.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="actionId"> The Id of the action to modify. This is technically the user action log id.</param>
    /// <param name="request"> The request that contains all the information about the modification.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ActionResponse>> ModifyActionAsync(Guid? actionId, ActionRequest request);

    /// <summary>
    /// Complete a login request using a passwordless code
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The passwordless login request that contains all the information used to complete login.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginResponse>> PasswordlessLoginAsync(PasswordlessLoginRequest request);

    /// <summary>
    /// Updates an authentication API key by given id
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the authentication key. If not provided a secure random api key will be generated.</param>
    /// <param name="request"> The request object that contains all the information needed to create the APIKey.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<APIKeyResponse>> PatchAPIKeyAsync(Guid? keyId, APIKeyRequest request);

    /// <summary>
    /// Updates, via PATCH, the application with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to update.</param>
    /// <param name="request"> The request that contains just the new application information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> PatchApplicationAsync(Guid? applicationId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the application role with the given Id for the application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
    /// <param name="roleId"> The Id of the role to update.</param>
    /// <param name="request"> The request that contains just the new role information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> PatchApplicationRoleAsync(Guid? applicationId, Guid? roleId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the connector with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="connectorId"> The Id of the connector to update.</param>
    /// <param name="request"> The request that contains just the new connector information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConnectorResponse>> PatchConnectorAsync(Guid? connectorId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the consent with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to update.</param>
    /// <param name="request"> The request that contains just the new consent information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConsentResponse>> PatchConsentAsync(Guid? consentId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the email template with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to update.</param>
    /// <param name="request"> The request that contains just the new email template information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EmailTemplateResponse>> PatchEmailTemplateAsync(Guid? emailTemplateId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the Entity Type with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityTypeId"> The Id of the Entity Type to update.</param>
    /// <param name="request"> The request that contains just the new Entity Type information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityTypeResponse>> PatchEntityTypeAsync(Guid? entityTypeId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the group with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> The Id of the group to update.</param>
    /// <param name="request"> The request that contains just the new group information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<GroupResponse>> PatchGroupAsync(Guid? groupId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the identity provider with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to update.</param>
    /// <param name="request"> The request object that contains just the updated identity provider information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderResponse>> PatchIdentityProviderAsync(Guid? identityProviderId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the available integrations.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains just the new integration information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IntegrationResponse>> PatchIntegrationsAsync(IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the lambda with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to update.</param>
    /// <param name="request"> The request that contains just the new lambda information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LambdaResponse>> PatchLambdaAsync(Guid? lambdaId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the message template with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messageTemplateId"> The Id of the message template to update.</param>
    /// <param name="request"> The request that contains just the new message template information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessageTemplateResponse>> PatchMessageTemplateAsync(Guid? messageTemplateId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the messenger with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messengerId"> The Id of the messenger to update.</param>
    /// <param name="request"> The request that contains just the new messenger information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessengerResponse>> PatchMessengerAsync(Guid? messengerId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the custom OAuth scope with the given Id for the application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the OAuth scope belongs to.</param>
    /// <param name="scopeId"> The Id of the OAuth scope to update.</param>
    /// <param name="request"> The request that contains just the new OAuth scope information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationOAuthScopeResponse>> PatchOAuthScopeAsync(Guid? applicationId, Guid? scopeId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the registration for the user with the given Id and the application defined in the request.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is going to be updated.</param>
    /// <param name="request"> The request that contains just the new registration information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RegistrationResponse>> PatchRegistrationAsync(Guid? userId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the system configuration.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains just the new system configuration information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<SystemConfigurationResponse>> PatchSystemConfigurationAsync(IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the tenant with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to update.</param>
    /// <param name="request"> The request that contains just the new tenant information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TenantResponse>> PatchTenantAsync(Guid? tenantId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the theme with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to update.</param>
    /// <param name="request"> The request that contains just the new theme information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ThemeResponse>> PatchThemeAsync(Guid? themeId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to update.</param>
    /// <param name="request"> The request that contains just the new user information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> PatchUserAsync(Guid? userId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the user action with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to update.</param>
    /// <param name="request"> The request that contains just the new user action information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionResponse>> PatchUserActionAsync(Guid? userActionId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, the user action reason with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to update.</param>
    /// <param name="request"> The request that contains just the new user action reason information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionReasonResponse>> PatchUserActionReasonAsync(Guid? userActionReasonId, IDictionary<string, object> request);

    /// <summary>
    /// Updates, via PATCH, a single User consent by Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <param name="request"> The request that contains just the new user consent information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserConsentResponse>> PatchUserConsentAsync(Guid? userConsentId, IDictionary<string, object> request);

    /// <summary>
    /// Reactivates the application with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to reactivate.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> ReactivateApplicationAsync(Guid? applicationId);

    /// <summary>
    /// Reactivates the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to reactivate.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> ReactivateUserAsync(Guid? userId);

    /// <summary>
    /// Reactivates the user action with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to reactivate.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionResponse>> ReactivateUserActionAsync(Guid? userActionId);

    /// <summary>
    /// Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The reconcile request that contains the data to reconcile the User.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginResponse>> ReconcileJWTAsync(IdentityProviderLoginRequest request);

    /// <summary>
    /// Request a refresh of the Entity search index. This API is not generally necessary and the search index will become consistent in a
    /// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
    /// if you are using the Search API or Delete Tenant API immediately following a Entity Create etc, you may wish to request a refresh to
    ///  ensure the index immediately current before making a query request to the search index.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RefreshEntitySearchIndexAsync();

    /// <summary>
    /// Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
    /// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
    /// if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
    ///  ensure the index immediately current before making a query request to the search index.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RefreshUserSearchIndexAsync();

    /// <summary>
    /// Regenerates any keys that are used by the FusionAuth Reactor.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RegenerateReactorKeysAsync();

    /// <summary>
    /// Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
    /// will create the user as well as register them for the application. This is called a Full Registration. However, if
    /// you only provide the UserRegistration object, then the user must already exist and they will be registered for the
    /// application. The user Id can also be provided and it will either be used to look up an existing user or it will be
    /// used for the newly created User.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> (Optional) The Id of the user being registered for the application and optionally created.</param>
    /// <param name="request"> The request that optionally contains the User and must contain the UserRegistration.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RegistrationResponse>> RegisterAsync(Guid? userId, RegistrationRequest request);

    /// <summary>
    /// Requests Elasticsearch to delete and rebuild the index for FusionAuth users or entities. Be very careful when running this request as it will 
    /// increase the CPU and I/O load on your database until the operation completes. Generally speaking you do not ever need to run this operation unless 
    /// instructed by FusionAuth support, or if you are migrating a database another system and you are not brining along the Elasticsearch index. 
    /// 
    /// You have been warned.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the index name.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> ReindexAsync(ReindexRequest request);

    /// <summary>
    /// Removes a user from the family with the given id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="familyId"> The Id of the family to remove the user from.</param>
    /// <param name="userId"> The Id of the user to remove from the family.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RemoveUserFromFamilyAsync(Guid? familyId, Guid? userId);

    /// <summary>
    /// Re-sends the verification email to the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<VerifyEmailResponse>> ResendEmailVerificationAsync(string email);

    /// <summary>
    /// Re-sends the verification email to the user. If the Application has configured a specific email template this will be used
    /// instead of the tenant configuration.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The unique Application Id to used to resolve an application specific email template.</param>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<VerifyEmailResponse>> ResendEmailVerificationWithApplicationTemplateAsync(Guid? applicationId, string email);

    /// <summary>
    /// Re-sends the application registration verification email to the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email address of the user that needs a new verification email.</param>
    /// <param name="applicationId"> The Id of the application to be verified.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<VerifyRegistrationResponse>> ResendRegistrationVerificationAsync(string email, Guid? applicationId);

    /// <summary>
    /// Retrieves an authentication API key for the given id
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the API key to retrieve.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<APIKeyResponse>> RetrieveAPIKeyAsync(Guid? keyId);

    /// <summary>
    /// Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="actionId"> The Id of the action to retrieve.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ActionResponse>> RetrieveActionAsync(Guid? actionId);

    /// <summary>
    /// Retrieves all the actions for the user with the given Id. This will return all time based actions that are active,
    /// and inactive as well as non-time based actions.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ActionResponse>> RetrieveActionsAsync(Guid? userId);

    /// <summary>
    /// Retrieves all the actions for the user with the given Id that are currently preventing the User from logging in.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ActionResponse>> RetrieveActionsPreventingLoginAsync(Guid? userId);

    /// <summary>
    /// Retrieves all the actions for the user with the given Id that are currently active.
    /// An active action means one that is time based and has not been canceled, and has not ended.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ActionResponse>> RetrieveActiveActionsAsync(Guid? userId);

    /// <summary>
    /// Retrieves the application for the given Id or all the applications if the Id is null.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> RetrieveApplicationAsync(Guid? applicationId);

    /// <summary>
    /// Retrieves all the applications.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> RetrieveApplicationsAsync();

    /// <summary>
    /// Retrieves a single audit log for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="auditLogId"> The Id of the audit log to retrieve.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<AuditLogResponse>> RetrieveAuditLogAsync(int? auditLogId);

    /// <summary>
    /// Retrieves the connector with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="connectorId"> The Id of the connector.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConnectorResponse>> RetrieveConnectorAsync(Guid? connectorId);

    /// <summary>
    /// Retrieves all the connectors.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConnectorResponse>> RetrieveConnectorsAsync();

    /// <summary>
    /// Retrieves the Consent for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> The Id of the consent.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConsentResponse>> RetrieveConsentAsync(Guid? consentId);

    /// <summary>
    /// Retrieves all the consent.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConsentResponse>> RetrieveConsentsAsync();

    /// <summary>
    /// Retrieves the daily active user report between the two instants. If you specify an application id, it will only
    /// return the daily active counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<DailyActiveUserReportResponse>> RetrieveDailyActiveReportAsync(Guid? applicationId, long? start, long? end);

    /// <summary>
    /// Retrieves the email template for the given Id. If you don't specify the id, this will return all the email templates.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> (Optional) The Id of the email template.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EmailTemplateResponse>> RetrieveEmailTemplateAsync(Guid? emailTemplateId);

    /// <summary>
    /// Creates a preview of the email template provided in the request. This allows you to preview an email template that
    /// hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
    /// will create the preview based on whatever is given.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the email template and optionally a locale to render it in.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PreviewResponse>> RetrieveEmailTemplatePreviewAsync(PreviewRequest request);

    /// <summary>
    /// Retrieves all the email templates.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EmailTemplateResponse>> RetrieveEmailTemplatesAsync();

    /// <summary>
    /// Retrieves the Entity for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityId"> The Id of the Entity.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityResponse>> RetrieveEntityAsync(Guid? entityId);

    /// <summary>
    /// Retrieves an Entity Grant for the given Entity and User/Entity.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityId"> The Id of the Entity.</param>
    /// <param name="recipientEntityId"> (Optional) The Id of the Entity that the Entity Grant is for.</param>
    /// <param name="userId"> (Optional) The Id of the User that the Entity Grant is for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityGrantResponse>> RetrieveEntityGrantAsync(Guid? entityId, Guid? recipientEntityId, Guid? userId);

    /// <summary>
    /// Retrieves the Entity Type for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityTypeId"> The Id of the Entity Type.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityTypeResponse>> RetrieveEntityTypeAsync(Guid? entityTypeId);

    /// <summary>
    /// Retrieves all the Entity Types.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityTypeResponse>> RetrieveEntityTypesAsync();

    /// <summary>
    /// Retrieves a single event log for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="eventLogId"> The Id of the event log to retrieve.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EventLogResponse>> RetrieveEventLogAsync(int? eventLogId);

    /// <summary>
    /// Retrieves all the families that a user belongs to.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The User's id</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FamilyResponse>> RetrieveFamiliesAsync(Guid? userId);

    /// <summary>
    /// Retrieves all the members of a family by the unique Family Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="familyId"> The unique Id of the Family.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FamilyResponse>> RetrieveFamilyMembersByFamilyIdAsync(Guid? familyId);

    /// <summary>
    /// Retrieves the form with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="formId"> The Id of the form.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FormResponse>> RetrieveFormAsync(Guid? formId);

    /// <summary>
    /// Retrieves the form field with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="fieldId"> The Id of the form field.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FormFieldResponse>> RetrieveFormFieldAsync(Guid? fieldId);

    /// <summary>
    /// Retrieves all the forms fields
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FormFieldResponse>> RetrieveFormFieldsAsync();

    /// <summary>
    /// Retrieves all the forms.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FormResponse>> RetrieveFormsAsync();

    /// <summary>
    /// Retrieves the group for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> The Id of the group.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<GroupResponse>> RetrieveGroupAsync(Guid? groupId);

    /// <summary>
    /// Retrieves all the groups.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<GroupResponse>> RetrieveGroupsAsync();

    /// <summary>
    /// Retrieves the IP Access Control List with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="ipAccessControlListId"> The Id of the IP Access Control List.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IPAccessControlListResponse>> RetrieveIPAccessControlListAsync(Guid? ipAccessControlListId);

    /// <summary>
    /// Retrieves the identity provider for the given Id or all the identity providers if the Id is null.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The identity provider Id.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderResponse>> RetrieveIdentityProviderAsync(Guid? identityProviderId);

    /// <summary>
    /// Retrieves one or more identity provider for the given type. For types such as Google, Facebook, Twitter and LinkedIn, only a single 
    /// identity provider can exist. For types such as OpenID Connect and SAMLv2 more than one identity provider can be configured so this request 
    /// may return multiple identity providers.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="type"> The type of the identity provider.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderResponse>> RetrieveIdentityProviderByTypeAsync(IdentityProviderType type);

    /// <summary>
    /// Retrieves all the identity providers.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderResponse>> RetrieveIdentityProvidersAsync();

    /// <summary>
    /// Retrieves all the actions for the user with the given Id that are currently inactive.
    /// An inactive action means one that is time based and has been canceled or has expired, or is not time based.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to fetch the actions for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ActionResponse>> RetrieveInactiveActionsAsync(Guid? userId);

    /// <summary>
    /// Retrieves all the applications that are currently inactive.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> RetrieveInactiveApplicationsAsync();

    /// <summary>
    /// Retrieves all the user actions that are currently inactive.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionResponse>> RetrieveInactiveUserActionsAsync();

    /// <summary>
    /// Retrieves the available integrations.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IntegrationResponse>> RetrieveIntegrationAsync();

    /// <summary>
    /// Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the public key (kid).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeyAsync(string keyId);

    /// <summary>
    /// Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the Application for which this key is used.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeyByApplicationIdAsync(string applicationId);

    /// <summary>
    /// Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PublicKeyResponse>> RetrieveJWTPublicKeysAsync();

    /// <summary>
    /// Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<JWKSResponse>> RetrieveJsonWebKeySetAsync();

    /// <summary>
    /// Retrieves the key for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the key.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<KeyResponse>> RetrieveKeyAsync(Guid? keyId);

    /// <summary>
    /// Retrieves all the keys.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<KeyResponse>> RetrieveKeysAsync();

    /// <summary>
    /// Retrieves the lambda for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LambdaResponse>> RetrieveLambdaAsync(Guid? lambdaId);

    /// <summary>
    /// Retrieves all the lambdas.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LambdaResponse>> RetrieveLambdasAsync();

    /// <summary>
    /// Retrieves all the lambdas for the provided type.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="type"> The type of the lambda to return.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LambdaResponse>> RetrieveLambdasByTypeAsync(LambdaType type);

    /// <summary>
    /// Retrieves the login report between the two instants. If you specify an application id, it will only return the
    /// login counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginReportResponse>> RetrieveLoginReportAsync(Guid? applicationId, long? start, long? end);

    /// <summary>
    /// Retrieves the message template for the given Id. If you don't specify the id, this will return all the message templates.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messageTemplateId"> (Optional) The Id of the message template.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessageTemplateResponse>> RetrieveMessageTemplateAsync(Guid? messageTemplateId);

    /// <summary>
    /// Creates a preview of the message template provided in the request, normalized to a given locale.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the email template and optionally a locale to render it in.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PreviewMessageTemplateResponse>> RetrieveMessageTemplatePreviewAsync(PreviewMessageTemplateRequest request);

    /// <summary>
    /// Retrieves all the message templates.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessageTemplateResponse>> RetrieveMessageTemplatesAsync();

    /// <summary>
    /// Retrieves the messenger with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messengerId"> The Id of the messenger.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessengerResponse>> RetrieveMessengerAsync(Guid? messengerId);

    /// <summary>
    /// Retrieves all the messengers.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessengerResponse>> RetrieveMessengersAsync();

    /// <summary>
    /// Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
    /// return the monthly active counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MonthlyActiveUserReportResponse>> RetrieveMonthlyActiveReportAsync(Guid? applicationId, long? start, long? end);

    /// <summary>
    /// Retrieves a custom OAuth scope.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the OAuth scope belongs to.</param>
    /// <param name="scopeId"> The Id of the OAuth scope to retrieve.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationOAuthScopeResponse>> RetrieveOAuthScopeAsync(Guid? applicationId, Guid? scopeId);

    /// <summary>
    /// Retrieves the Oauth2 configuration for the application for the given Application Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the Application to retrieve OAuth configuration.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<OAuthConfigurationResponse>> RetrieveOauthConfigurationAsync(Guid? applicationId);

    /// <summary>
    /// Returns the well known OpenID Configuration JSON document
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<OpenIdConfiguration>> RetrieveOpenIdConfigurationAsync();

    /// <summary>
    /// Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided 
    /// through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
    /// 
    /// This API does not require an API key.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PasswordValidationRulesResponse>> RetrievePasswordValidationRulesAsync();

    /// <summary>
    /// Retrieves the password validation rules for a specific tenant.
    /// 
    /// This API does not require an API key.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PasswordValidationRulesResponse>> RetrievePasswordValidationRulesWithTenantIdAsync(Guid? tenantId);

    /// <summary>
    /// Retrieves all the children for the given parent email address.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="parentEmail"> The email of the parent.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PendingResponse>> RetrievePendingChildrenAsync(string parentEmail);

    /// <summary>
    /// Retrieve a pending identity provider link. This is useful to validate a pending link and retrieve meta-data about the identity provider link.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="pendingLinkId"> The pending link Id.</param>
    /// <param name="userId"> The optional userId. When provided additional meta-data will be provided to identify how many links if any the user already has.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderPendingLinkResponse>> RetrievePendingLinkAsync(string pendingLinkId, Guid? userId);

    /// <summary>
    /// Retrieves the FusionAuth Reactor metrics.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ReactorMetricsResponse>> RetrieveReactorMetricsAsync();

    /// <summary>
    /// Retrieves the FusionAuth Reactor status.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ReactorResponse>> RetrieveReactorStatusAsync();

    /// <summary>
    /// Retrieves the last number of login records.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="offset"> The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.</param>
    /// <param name="limit"> (Optional, defaults to 10) The number of records to retrieve.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RecentLoginResponse>> RetrieveRecentLoginsAsync(int? offset, int? limit);

    /// <summary>
    /// Retrieves a single refresh token by unique Id. This is not the same thing as the string value of the refresh token. If you have that, you already have what you need.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tokenId"> The Id of the token.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RefreshTokenResponse>> RetrieveRefreshTokenByIdAsync(Guid? tokenId);

    /// <summary>
    /// Retrieves the refresh tokens that belong to the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RefreshTokenResponse>> RetrieveRefreshTokensAsync(Guid? userId);

    /// <summary>
    /// Retrieves the user registration for the user with the given Id and the given application id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <param name="applicationId"> The Id of the application.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RegistrationResponse>> RetrieveRegistrationAsync(Guid? userId, Guid? applicationId);

    /// <summary>
    /// Retrieves the registration report between the two instants. If you specify an application id, it will only return
    /// the registration counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RegistrationReportResponse>> RetrieveRegistrationReportAsync(Guid? applicationId, long? start, long? end);

    /// <summary>
    /// Retrieve the status of a re-index process. A status code of 200 indicates the re-index is in progress, a status code of  
    /// 404 indicates no re-index is in progress.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RetrieveReindexStatusAsync();

    /// <summary>
    /// Retrieves the system configuration.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<SystemConfigurationResponse>> RetrieveSystemConfigurationAsync();

    /// <summary>
    /// Retrieves the tenant for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TenantResponse>> RetrieveTenantAsync(Guid? tenantId);

    /// <summary>
    /// Retrieves all the tenants.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TenantResponse>> RetrieveTenantsAsync();

    /// <summary>
    /// Retrieves the theme for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> The Id of the theme.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ThemeResponse>> RetrieveThemeAsync(Guid? themeId);

    /// <summary>
    /// Retrieves all the themes.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ThemeResponse>> RetrieveThemesAsync();

    /// <summary>
    /// Retrieves the totals report. This contains all the total counts for each application and the global registration
    /// count.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TotalsReportResponse>> RetrieveTotalReportAsync();

    /// <summary>
    /// Retrieve two-factor recovery codes for a user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to retrieve Two Factor recovery codes.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TwoFactorRecoveryCodeResponse>> RetrieveTwoFactorRecoveryCodesAsync(Guid? userId);

    /// <summary>
    /// Retrieve a user's two-factor status.
    /// 
    /// This can be used to see if a user will need to complete a two-factor challenge to complete a login,
    /// and optionally identify the state of the two-factor trust across various applications.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The user Id to retrieve the Two-Factor status.</param>
    /// <param name="applicationId"> The optional applicationId to verify.</param>
    /// <param name="twoFactorTrustId"> The optional two-factor trust Id to verify.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TwoFactorStatusResponse>> RetrieveTwoFactorStatusAsync(Guid? userId, Guid? applicationId, string twoFactorTrustId);

    /// <summary>
    /// Retrieves the user for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> RetrieveUserAsync(Guid? userId);

    /// <summary>
    /// Retrieves the user action for the given Id. If you pass in null for the id, this will return all the user
    /// actions.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> (Optional) The Id of the user action.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionResponse>> RetrieveUserActionAsync(Guid? userActionId);

    /// <summary>
    /// Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all the user
    /// action reasons.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> (Optional) The Id of the user action reason.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionReasonResponse>> RetrieveUserActionReasonAsync(Guid? userActionReasonId);

    /// <summary>
    /// Retrieves all the user action reasons.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionReasonResponse>> RetrieveUserActionReasonsAsync();

    /// <summary>
    /// Retrieves all the user actions.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionResponse>> RetrieveUserActionsAsync();

    /// <summary>
    /// Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
    /// password workflow has been initiated and you may not know the user's email or username.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="changePasswordId"> The unique change password Id that was sent via email or returned by the Forgot Password API.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> RetrieveUserByChangePasswordIdAsync(string changePasswordId);

    /// <summary>
    /// Retrieves the user for the given email.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="email"> The email of the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> RetrieveUserByEmailAsync(string email);

    /// <summary>
    /// Retrieves the user for the loginId. The loginId can be either the username or the email.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="loginId"> The email or username of the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> RetrieveUserByLoginIdAsync(string loginId);

    /// <summary>
    /// Retrieves the user for the given username.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="username"> The username of the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> RetrieveUserByUsernameAsync(string username);

    /// <summary>
    /// Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
    /// password workflow has been initiated and you may not know the user's email or username.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="verificationId"> The unique verification Id that has been set on the user object.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> RetrieveUserByVerificationIdAsync(string verificationId);

    /// <summary>
    /// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
    /// 
    /// This API is useful if you want to build your own login workflow to complete a device grant.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="client_id"> The client id.</param>
    /// <param name="client_secret"> The client id.</param>
    /// <param name="user_code"> The end-user verification code.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RetrieveUserCodeAsync(string client_id, string client_secret, string user_code);

    /// <summary>
    /// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
    /// 
    /// This API is useful if you want to build your own login workflow to complete a device grant.
    /// 
    /// This request will require an API key.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="user_code"> The end-user verification code.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RetrieveUserCodeUsingAPIKeyAsync(string user_code);

    /// <summary>
    /// Retrieves all the comments for the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserCommentResponse>> RetrieveUserCommentsAsync(Guid? userId);

    /// <summary>
    /// Retrieve a single User consent by Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> The User consent Id</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserConsentResponse>> RetrieveUserConsentAsync(Guid? userConsentId);

    /// <summary>
    /// Retrieves all the consents for a User.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The User's Id</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserConsentResponse>> RetrieveUserConsentsAsync(Guid? userId);

    /// <summary>
    /// Call the UserInfo endpoint to retrieve User Claims from the access token issued by FusionAuth.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserinfoResponse>> RetrieveUserInfoFromAccessTokenAsync(string encodedJWT);

    /// <summary>
    /// Retrieve a single Identity Provider user (link).
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The unique Id of the identity provider.</param>
    /// <param name="identityProviderUserId"> The unique Id of the user in the 3rd party identity provider.</param>
    /// <param name="userId"> The unique Id of the FusionAuth user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderLinkResponse>> RetrieveUserLinkAsync(Guid? identityProviderId, string identityProviderUserId, Guid? userId);

    /// <summary>
    /// Retrieve all Identity Provider users (links) for the user. Specify the optional identityProviderId to retrieve links for a particular IdP.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> (Optional) The unique Id of the identity provider. Specify this value to reduce the links returned to those for a particular IdP.</param>
    /// <param name="userId"> The unique Id of the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderLinkResponse>> RetrieveUserLinksByUserIdAsync(Guid? identityProviderId, Guid? userId);

    /// <summary>
    /// Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
    /// login counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="userId"> The userId id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginReportResponse>> RetrieveUserLoginReportAsync(Guid? applicationId, Guid? userId, long? start, long? end);

    /// <summary>
    /// Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
    /// login counts for that application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> (Optional) The application id.</param>
    /// <param name="loginId"> The userId id.</param>
    /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
    /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginReportResponse>> RetrieveUserLoginReportByLoginIdAsync(Guid? applicationId, string loginId, long? start, long? end);

    /// <summary>
    /// Retrieves the last number of login records for a user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user.</param>
    /// <param name="offset"> The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.</param>
    /// <param name="limit"> (Optional, defaults to 10) The number of records to retrieve.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RecentLoginResponse>> RetrieveUserRecentLoginsAsync(Guid? userId, int? offset, int? limit);

    /// <summary>
    /// Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> RetrieveUserUsingJWTAsync(string encodedJWT);

    /// <summary>
    /// Retrieves the FusionAuth version string.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<VersionResponse>> RetrieveVersionAsync();

    /// <summary>
    /// Retrieves the WebAuthn credential for the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="id"> The Id of the WebAuthn credential.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebAuthnCredentialResponse>> RetrieveWebAuthnCredentialAsync(Guid? id);

    /// <summary>
    /// Retrieves all WebAuthn credentials for the given user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The user's ID.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebAuthnCredentialResponse>> RetrieveWebAuthnCredentialsForUserAsync(Guid? userId);

    /// <summary>
    /// Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="webhookId"> (Optional) The Id of the webhook.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebhookResponse>> RetrieveWebhookAsync(Guid? webhookId);

    /// <summary>
    /// Retrieves all the webhooks.
    /// This is an asynchronous method.
    /// </summary>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebhookResponse>> RetrieveWebhooksAsync();

    /// <summary>
    /// Revokes refresh tokens.
    /// 
    /// Usage examples:
    ///   - Delete a single refresh token, pass in only the token.
    ///       revokeRefreshToken(token)
    /// 
    ///   - Delete all refresh tokens for a user, pass in only the userId.
    ///       revokeRefreshToken(null, userId)
    /// 
    ///   - Delete all refresh tokens for a user for a specific application, pass in both the userId and the applicationId.
    ///       revokeRefreshToken(null, userId, applicationId)
    /// 
    ///   - Delete all refresh tokens for an application
    ///       revokeRefreshToken(null, null, applicationId)
    /// 
    /// Note: <code>null</code> may be handled differently depending upon the programming language.
    /// 
    /// See also: (method names may vary by language... but you'll figure it out)
    /// 
    ///  - revokeRefreshTokenById
    ///  - revokeRefreshTokenByToken
    ///  - revokeRefreshTokensByUserId
    ///  - revokeRefreshTokensByApplicationId
    ///  - revokeRefreshTokensByUserIdForApplication
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="token"> (Optional) The refresh token to delete.</param>
    /// <param name="userId"> (Optional) The user Id whose tokens to delete.</param>
    /// <param name="applicationId"> (Optional) The application Id of the tokens to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RevokeRefreshTokenAsync(string token, Guid? userId, Guid? applicationId);

    /// <summary>
    /// Revokes a single refresh token by the unique Id. The unique Id is not sensitive as it cannot be used to obtain another JWT.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tokenId"> The unique Id of the token to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RevokeRefreshTokenByIdAsync(Guid? tokenId);

    /// <summary>
    /// Revokes a single refresh token by using the actual refresh token value. This refresh token value is sensitive, so  be careful with this API request.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="token"> The refresh token to delete.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RevokeRefreshTokenByTokenAsync(string token);

    /// <summary>
    /// Revoke all refresh tokens that belong to an application by applicationId.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The unique Id of the application that you want to delete all refresh tokens for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RevokeRefreshTokensByApplicationIdAsync(Guid? applicationId);

    /// <summary>
    /// Revoke all refresh tokens that belong to a user by user Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The unique Id of the user that you want to delete all refresh tokens for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RevokeRefreshTokensByUserIdAsync(Guid? userId);

    /// <summary>
    /// Revoke all refresh tokens that belong to a user by user Id for a specific application by applicationId.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The unique Id of the user that you want to delete all refresh tokens for.</param>
    /// <param name="applicationId"> The unique Id of the application that you want to delete refresh tokens for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RevokeRefreshTokensByUserIdForApplicationAsync(Guid? userId, Guid? applicationId);

    /// <summary>
    /// Revokes refresh tokens using the information in the JSON body. The handling for this method is the same as the revokeRefreshToken method
    /// and is based on the information you provide in the RefreshDeleteRequest object. See that method for additional information.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request information used to revoke the refresh tokens.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RevokeRefreshTokensWithRequestAsync(RefreshTokenRevokeRequest request);

    /// <summary>
    /// Revokes a single User consent by Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> RevokeUserConsentAsync(Guid? userConsentId);

    /// <summary>
    /// Searches applications with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationSearchResponse>> SearchApplicationsAsync(ApplicationSearchRequest request);

    /// <summary>
    /// Searches the audit logs with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<AuditLogSearchResponse>> SearchAuditLogsAsync(AuditLogSearchRequest request);

    /// <summary>
    /// Searches consents with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConsentSearchResponse>> SearchConsentsAsync(ConsentSearchRequest request);

    /// <summary>
    /// Searches email templates with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EmailTemplateSearchResponse>> SearchEmailTemplatesAsync(EmailTemplateSearchRequest request);

    /// <summary>
    /// Searches entities with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntitySearchResponse>> SearchEntitiesAsync(EntitySearchRequest request);

    /// <summary>
    /// Retrieves the entities for the given ids. If any Id is invalid, it is ignored.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="ids"> The entity ids to search for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntitySearchResponse>> SearchEntitiesByIdsAsync(List<string> ids);

    /// <summary>
    /// Searches Entity Grants with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityGrantSearchResponse>> SearchEntityGrantsAsync(EntityGrantSearchRequest request);

    /// <summary>
    /// Searches the entity types with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityTypeSearchResponse>> SearchEntityTypesAsync(EntityTypeSearchRequest request);

    /// <summary>
    /// Searches the event logs with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EventLogSearchResponse>> SearchEventLogsAsync(EventLogSearchRequest request);

    /// <summary>
    /// Searches group members with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<GroupMemberSearchResponse>> SearchGroupMembersAsync(GroupMemberSearchRequest request);

    /// <summary>
    /// Searches groups with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<GroupSearchResponse>> SearchGroupsAsync(GroupSearchRequest request);

    /// <summary>
    /// Searches the IP Access Control Lists with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IPAccessControlListSearchResponse>> SearchIPAccessControlListsAsync(IPAccessControlListSearchRequest request);

    /// <summary>
    /// Searches identity providers with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderSearchResponse>> SearchIdentityProvidersAsync(IdentityProviderSearchRequest request);

    /// <summary>
    /// Searches keys with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<KeySearchResponse>> SearchKeysAsync(KeySearchRequest request);

    /// <summary>
    /// Searches lambdas with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LambdaSearchResponse>> SearchLambdasAsync(LambdaSearchRequest request);

    /// <summary>
    /// Searches the login records with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginRecordSearchResponse>> SearchLoginRecordsAsync(LoginRecordSearchRequest request);

    /// <summary>
    /// Searches tenants with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TenantSearchResponse>> SearchTenantsAsync(TenantSearchRequest request);

    /// <summary>
    /// Searches themes with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ThemeSearchResponse>> SearchThemesAsync(ThemeSearchRequest request);

    /// <summary>
    /// Searches user comments with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserCommentSearchResponse>> SearchUserCommentsAsync(UserCommentSearchRequest request);

    /// <summary>
    /// Retrieves the users for the given ids. If any Id is invalid, it is ignored.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="ids"> The user ids to search for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    [Obsolete("This method has been renamed to SearchUsersByIdsAsync, use that method instead.")]
    Task<ClientResponse<SearchResponse>> SearchUsersAsync(List<string> ids);

    /// <summary>
    /// Retrieves the users for the given ids. If any Id is invalid, it is ignored.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="ids"> The user ids to search for.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<SearchResponse>> SearchUsersByIdsAsync(List<string> ids);

    /// <summary>
    /// Retrieves the users for the given search criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
    /// and sortFields.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<SearchResponse>> SearchUsersByQueryAsync(SearchRequest request);

    /// <summary>
    /// Retrieves the users for the given search criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
    /// and sortFields.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    [Obsolete("This method has been renamed to SearchUsersByQueryAsync, use that method instead.")]
    Task<ClientResponse<SearchResponse>> SearchUsersByQueryStringAsync(SearchRequest request);

    /// <summary>
    /// Searches webhooks with the specified criteria and pagination.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The search criteria and pagination information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebhookSearchResponse>> SearchWebhooksAsync(WebhookSearchRequest request);

    /// <summary>
    /// Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
    /// pairs in the email template.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> The Id for the template.</param>
    /// <param name="request"> The send email request that contains all the information used to send the email.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<SendResponse>> SendEmailAsync(Guid? emailTemplateId, SendRequest request);

    /// <summary>
    /// Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains the parent email.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> SendFamilyRequestEmailAsync(FamilyEmailRequest request);

    /// <summary>
    /// Send a passwordless authentication code in an email to complete login.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The passwordless send request that contains all the information used to send an email containing a code.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> SendPasswordlessCodeAsync(PasswordlessSendRequest request);

    /// <summary>
    /// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all the information used to send the code.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    [Obsolete("This method has been renamed to SendTwoFactorCodeForEnableDisableAsync, use that method instead.")]
    Task<ClientResponse<RESTVoid>> SendTwoFactorCodeAsync(TwoFactorSendRequest request);

    /// <summary>
    /// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all the information used to send the code.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> SendTwoFactorCodeForEnableDisableAsync(TwoFactorSendRequest request);

    /// <summary>
    /// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="twoFactorId"> The Id returned by the Login API necessary to complete Two Factor authentication.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    [Obsolete("This method has been renamed to SendTwoFactorCodeForLoginUsingMethodAsync, use that method instead.")]
    Task<ClientResponse<RESTVoid>> SendTwoFactorCodeForLoginAsync(string twoFactorId);

    /// <summary>
    /// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="twoFactorId"> The Id returned by the Login API necessary to complete Two Factor authentication.</param>
    /// <param name="request"> The Two Factor send request that contains all the information used to send the Two Factor code to the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> SendTwoFactorCodeForLoginUsingMethodAsync(string twoFactorId, TwoFactorSendRequest request);

    /// <summary>
    /// Begins a login request for a 3rd party login that requires user interaction such as HYPR.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The third-party login request that contains information from the third-party login
    /// providers that FusionAuth uses to reconcile the user's account.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderStartLoginResponse>> StartIdentityProviderLoginAsync(IdentityProviderStartLoginRequest request);

    /// <summary>
    /// Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
    /// Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The passwordless start request that contains all the information used to begin the passwordless login request.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<PasswordlessStartResponse>> StartPasswordlessLoginAsync(PasswordlessStartRequest request);

    /// <summary>
    /// Start a Two-Factor login request by generating a two-factor identifier. This code can then be sent to the Two Factor Send 
    /// API (/api/two-factor/send)in order to send a one-time use code to a user. You can also use one-time use code returned 
    /// to send the code out-of-band. The Two-Factor login is completed by making a request to the Two-Factor Login 
    /// API (/api/two-factor/login). with the two-factor identifier and the one-time use code.
    /// 
    /// This API is intended to allow you to begin a Two-Factor login outside a normal login that originated from the Login API (/api/login).
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The Two-Factor start request that contains all the information used to begin the Two-Factor login request.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TwoFactorStartResponse>> StartTwoFactorLoginAsync(TwoFactorStartRequest request);

    /// <summary>
    /// Start a WebAuthn authentication ceremony by generating a new challenge for the user
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> An object containing data necessary for starting the authentication ceremony</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebAuthnStartResponse>> StartWebAuthnLoginAsync(WebAuthnStartRequest request);

    /// <summary>
    /// Start a WebAuthn registration ceremony by generating a new challenge for the user
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> An object containing data necessary for starting the registration ceremony</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebAuthnRegisterStartResponse>> StartWebAuthnRegistrationAsync(WebAuthnRegisterStartRequest request);

    /// <summary>
    /// Complete login using a 2FA challenge
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LoginResponse>> TwoFactorLoginAsync(TwoFactorLoginRequest request);

    /// <summary>
    /// Updates an API key by given id
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="apiKeyId"> The Id of the API key to update.</param>
    /// <param name="request"> The request object that contains all the information used to create the API Key.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<APIKeyResponse>> UpdateAPIKeyAsync(Guid? apiKeyId, APIKeyRequest request);

    /// <summary>
    /// Updates the application with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application to update.</param>
    /// <param name="request"> The request that contains all the new application information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> UpdateApplicationAsync(Guid? applicationId, ApplicationRequest request);

    /// <summary>
    /// Updates the application role with the given Id for the application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
    /// <param name="roleId"> The Id of the role to update.</param>
    /// <param name="request"> The request that contains all the new role information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationResponse>> UpdateApplicationRoleAsync(Guid? applicationId, Guid? roleId, ApplicationRequest request);

    /// <summary>
    /// Updates the connector with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="connectorId"> The Id of the connector to update.</param>
    /// <param name="request"> The request object that contains all the new connector information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConnectorResponse>> UpdateConnectorAsync(Guid? connectorId, ConnectorRequest request);

    /// <summary>
    /// Updates the consent with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="consentId"> The Id of the consent to update.</param>
    /// <param name="request"> The request that contains all the new consent information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ConsentResponse>> UpdateConsentAsync(Guid? consentId, ConsentRequest request);

    /// <summary>
    /// Updates the email template with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="emailTemplateId"> The Id of the email template to update.</param>
    /// <param name="request"> The request that contains all the new email template information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EmailTemplateResponse>> UpdateEmailTemplateAsync(Guid? emailTemplateId, EmailTemplateRequest request);

    /// <summary>
    /// Updates the Entity with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityId"> The Id of the Entity to update.</param>
    /// <param name="request"> The request that contains all the new Entity information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityResponse>> UpdateEntityAsync(Guid? entityId, EntityRequest request);

    /// <summary>
    /// Updates the Entity Type with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityTypeId"> The Id of the Entity Type to update.</param>
    /// <param name="request"> The request that contains all the new Entity Type information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityTypeResponse>> UpdateEntityTypeAsync(Guid? entityTypeId, EntityTypeRequest request);

    /// <summary>
    /// Updates the permission with the given Id for the entity type.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityTypeId"> The Id of the entityType that the permission belongs to.</param>
    /// <param name="permissionId"> The Id of the permission to update.</param>
    /// <param name="request"> The request that contains all the new permission information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<EntityTypeResponse>> UpdateEntityTypePermissionAsync(Guid? entityTypeId, Guid? permissionId, EntityTypeRequest request);

    /// <summary>
    /// Updates the form with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="formId"> The Id of the form to update.</param>
    /// <param name="request"> The request object that contains all the new form information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FormResponse>> UpdateFormAsync(Guid? formId, FormRequest request);

    /// <summary>
    /// Updates the form field with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="fieldId"> The Id of the form field to update.</param>
    /// <param name="request"> The request object that contains all the new form field information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<FormFieldResponse>> UpdateFormFieldAsync(Guid? fieldId, FormFieldRequest request);

    /// <summary>
    /// Updates the group with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="groupId"> The Id of the group to update.</param>
    /// <param name="request"> The request that contains all the new group information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<GroupResponse>> UpdateGroupAsync(Guid? groupId, GroupRequest request);

    /// <summary>
    /// Creates a member in a group.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request object that contains all the information used to create the group member(s).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MemberResponse>> UpdateGroupMembersAsync(MemberRequest request);

    /// <summary>
    /// Updates the IP Access Control List with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="accessControlListId"> The Id of the IP Access Control List to update.</param>
    /// <param name="request"> The request that contains all the new IP Access Control List information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IPAccessControlListResponse>> UpdateIPAccessControlListAsync(Guid? accessControlListId, IPAccessControlListRequest request);

    /// <summary>
    /// Updates the identity provider with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="identityProviderId"> The Id of the identity provider to update.</param>
    /// <param name="request"> The request object that contains the updated identity provider.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IdentityProviderResponse>> UpdateIdentityProviderAsync(Guid? identityProviderId, IdentityProviderRequest request);

    /// <summary>
    /// Updates the available integrations.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains all the new integration information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<IntegrationResponse>> UpdateIntegrationsAsync(IntegrationRequest request);

    /// <summary>
    /// Updates the key with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="keyId"> The Id of the key to update.</param>
    /// <param name="request"> The request that contains all the new key information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<KeyResponse>> UpdateKeyAsync(Guid? keyId, KeyRequest request);

    /// <summary>
    /// Updates the lambda with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="lambdaId"> The Id of the lambda to update.</param>
    /// <param name="request"> The request that contains all the new lambda information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<LambdaResponse>> UpdateLambdaAsync(Guid? lambdaId, LambdaRequest request);

    /// <summary>
    /// Updates the message template with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messageTemplateId"> The Id of the message template to update.</param>
    /// <param name="request"> The request that contains all the new message template information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessageTemplateResponse>> UpdateMessageTemplateAsync(Guid? messageTemplateId, MessageTemplateRequest request);

    /// <summary>
    /// Updates the messenger with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="messengerId"> The Id of the messenger to update.</param>
    /// <param name="request"> The request object that contains all the new messenger information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<MessengerResponse>> UpdateMessengerAsync(Guid? messengerId, MessengerRequest request);

    /// <summary>
    /// Updates the OAuth scope with the given Id for the application.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="applicationId"> The Id of the application that the OAuth scope belongs to.</param>
    /// <param name="scopeId"> The Id of the OAuth scope to update.</param>
    /// <param name="request"> The request that contains all the new OAuth scope information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ApplicationOAuthScopeResponse>> UpdateOAuthScopeAsync(Guid? applicationId, Guid? scopeId, ApplicationOAuthScopeRequest request);

    /// <summary>
    /// Updates the registration for the user with the given Id and the application defined in the request.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user whose registration is going to be updated.</param>
    /// <param name="request"> The request that contains all the new registration information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RegistrationResponse>> UpdateRegistrationAsync(Guid? userId, RegistrationRequest request);

    /// <summary>
    /// Updates the system configuration.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains all the new system configuration information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<SystemConfigurationResponse>> UpdateSystemConfigurationAsync(SystemConfigurationRequest request);

    /// <summary>
    /// Updates the tenant with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="tenantId"> The Id of the tenant to update.</param>
    /// <param name="request"> The request that contains all the new tenant information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<TenantResponse>> UpdateTenantAsync(Guid? tenantId, TenantRequest request);

    /// <summary>
    /// Updates the theme with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="themeId"> The Id of the theme to update.</param>
    /// <param name="request"> The request that contains all the new theme information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ThemeResponse>> UpdateThemeAsync(Guid? themeId, ThemeRequest request);

    /// <summary>
    /// Updates the user with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userId"> The Id of the user to update.</param>
    /// <param name="request"> The request that contains all the new user information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserResponse>> UpdateUserAsync(Guid? userId, UserRequest request);

    /// <summary>
    /// Updates the user action with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionId"> The Id of the user action to update.</param>
    /// <param name="request"> The request that contains all the new user action information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionResponse>> UpdateUserActionAsync(Guid? userActionId, UserActionRequest request);

    /// <summary>
    /// Updates the user action reason with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userActionReasonId"> The Id of the user action reason to update.</param>
    /// <param name="request"> The request that contains all the new user action reason information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserActionReasonResponse>> UpdateUserActionReasonAsync(Guid? userActionReasonId, UserActionReasonRequest request);

    /// <summary>
    /// Updates a single User consent by Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="userConsentId"> The User Consent Id</param>
    /// <param name="request"> The request that contains the user consent information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<UserConsentResponse>> UpdateUserConsentAsync(Guid? userConsentId, UserConsentRequest request);

    /// <summary>
    /// Updates the webhook with the given Id.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="webhookId"> The Id of the webhook to update.</param>
    /// <param name="request"> The request that contains all the new webhook information.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<WebhookResponse>> UpdateWebhookAsync(Guid? webhookId, WebhookRequest request);

    /// <summary>
    /// Creates or updates an Entity Grant. This is when a User/Entity is granted permissions to an Entity.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="entityId"> The Id of the Entity that the User/Entity is being granted access to.</param>
    /// <param name="request"> The request object that contains all the information used to create the Entity Grant.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> UpsertEntityGrantAsync(Guid? entityId, EntityGrantRequest request);

    /// <summary>
    /// Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
    /// If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="user_code"> The end-user verification code.</param>
    /// <param name="client_id"> The client id.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> ValidateDeviceAsync(string user_code, string client_id);

    /// <summary>
    /// Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
    /// signed and not expired.
    /// <p>
    /// This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="encodedJWT"> The encoded JWT (access token).</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<ValidateResponse>> ValidateJWTAsync(string encodedJWT);

    /// <summary>
    /// It's a JWT vending machine!
    /// 
    /// Issue a new access token (JWT) with the provided claims in the request. This JWT is not scoped to a tenant or user, it is a free form 
    /// token that will contain what claims you provide.
    /// <p>
    /// The iat, exp and jti claims will be added by FusionAuth, all other claims must be provided by the caller.
    /// 
    /// If a TTL is not provided in the request, the TTL will be retrieved from the default Tenant or the Tenant specified on the request either 
    /// by way of the X-FusionAuth-TenantId request header, or a tenant scoped API key.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains all the claims for this JWT.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<JWTVendResponse>> VendJWTAsync(JWTVendRequest request);

    /// <summary>
    /// Confirms a email verification. The Id given is usually from an email sent to the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="verificationId"> The email verification Id sent to the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    [Obsolete("This method has been renamed to VerifyEmailAddressAsync and changed to take a JSON request body, use that method instead.")]
    Task<ClientResponse<RESTVoid>> VerifyEmailAsync(string verificationId);

    /// <summary>
    /// Confirms a user's email address. 
    /// 
    /// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When 
    /// the tenant is configured to gate a user until their email address is verified, this procedures requires two values instead of one. 
    /// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The 
    /// two values together are able to confirm a user's email address and mark the user's email address as verified.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the verificationId and optional one-time use code paired with the verificationId.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> VerifyEmailAddressAsync(VerifyEmailRequest request);

    /// <summary>
    /// Administratively verify a user's email address. Use this method to bypass email verification for the user.
    /// 
    /// The request body will contain the userId to be verified. An API key is required when sending the userId in the request body.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the userId to verify.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> VerifyEmailAddressByUserIdAsync(VerifyEmailRequest request);

    /// <summary>
    /// Confirms an application registration. The Id given is usually from an email sent to the user.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="verificationId"> The registration verification Id sent to the user.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    [Obsolete("This method has been renamed to VerifyUserRegistrationAsync and changed to take a JSON request body, use that method instead.")]
    Task<ClientResponse<RESTVoid>> VerifyRegistrationAsync(string verificationId);

    /// <summary>
    /// Confirms a user's registration. 
    /// 
    /// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When 
    /// the application is configured to gate a user until their registration is verified, this procedures requires two values instead of one. 
    /// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The 
    /// two values together are able to confirm a user's registration and mark the user's registration as verified.
    /// This is an asynchronous method.
    /// </summary>
    /// <param name="request"> The request that contains the verificationId and optional one-time use code paired with the verificationId.</param>
    /// <returns>
    /// When successful, the response will contain the log of the action. If there was a validation error or any
    /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
    /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
    /// IOException.
    /// </returns>
    Task<ClientResponse<RESTVoid>> VerifyUserRegistrationAsync(VerifyRegistrationRequest request);
  }

 public interface IFusionAuthSyncClient {

   /// <summary>
   /// Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
   /// "actioner". Both user ids are required in the request object.
   /// </summary>
   /// <param name="request"> The action request that includes all the information about the action being taken including
    /// the Id of the action, any options and the duration (if applicable).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ActionResponse> ActionUser(ActionRequest request);

   /// <summary>
   /// Activates the FusionAuth Reactor using a license Id and optionally a license text (for air-gapped deployments)
   /// </summary>
   /// <param name="request"> An optional request that contains the license text to activate Reactor (useful for air-gap deployments of FusionAuth).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> ActivateReactor(ReactorRequest request);

   /// <summary>
   /// Adds a user to an existing family. The family Id must be specified.
   /// </summary>
   /// <param name="familyId"> The Id of the family.</param>
   /// <param name="request"> The request object that contains all the information used to determine which user to add to the family.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FamilyResponse> AddUserToFamily(Guid? familyId, FamilyRequest request);

   /// <summary>
   /// Approve a device grant.
   /// </summary>
   /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.</param>
   /// <param name="client_secret"> (Optional) The client secret. This value will be required if client authentication is enabled.</param>
   /// <param name="token"> The access token used to identify the user.</param>
   /// <param name="user_code"> The end-user verification code.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<DeviceApprovalResponse> ApproveDevice(string client_id, string client_secret, string token, string user_code);

   /// <summary>
   /// Cancels the user action.
   /// </summary>
   /// <param name="actionId"> The action Id of the action to cancel.</param>
   /// <param name="request"> The action request that contains the information about the cancellation.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ActionResponse> CancelAction(Guid? actionId, ActionRequest request);

   /// <summary>
   /// Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
   /// and they clicked on a link to reset their password.
   /// 
   /// As of version 1.32.2, prefer sending the changePasswordId in the request body. To do this, omit the first parameter, and set
   /// the value in the request body.
   /// </summary>
   /// <param name="changePasswordId"> The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.</param>
   /// <param name="request"> The change password request that contains all the information used to change the password.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ChangePasswordResponse> ChangePassword(string changePasswordId, ChangePasswordRequest request);

   /// <summary>
   /// Changes a user's password using their identity (loginId and password). Using a loginId instead of the changePasswordId
   /// bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
   /// method.
   /// </summary>
   /// <param name="request"> The change password request that contains all the information used to change the password.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> ChangePasswordByIdentity(ChangePasswordRequest request);

   /// <summary>
   /// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
   /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   /// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
   /// 
   /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   /// </summary>
   /// <param name="changePasswordId"> The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> CheckChangePasswordUsingId(string changePasswordId);

   /// <summary>
   /// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
   /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   /// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
   /// 
   /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   /// </summary>
   /// <param name="encodedJWT"> The encoded JWT (access token).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> CheckChangePasswordUsingJWT(string encodedJWT);

   /// <summary>
   /// Check to see if the user must obtain a Trust Request Id in order to complete a change password request.
   /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
   /// your password, you must obtain a Trust Request Id by completing a Two-Factor Step-Up authentication.
   /// 
   /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
   /// </summary>
   /// <param name="loginId"> The loginId of the User that you intend to change the password for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> CheckChangePasswordUsingLoginId(string loginId);

   /// <summary>
   /// Make a Client Credentials grant request to obtain an access token.
   /// </summary>
   /// <param name="client_id"> (Optional) The client identifier. The client Id is the Id of the FusionAuth Entity in which you are attempting to authenticate.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
   /// <param name="client_secret"> (Optional) The client secret used to authenticate this request.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
   /// <param name="scope"> (Optional) This parameter is used to indicate which target entity you are requesting access. To request access to an entity, use the format target-entity:&lt;target-entity-id&gt;:&lt;roles&gt;. Roles are an optional comma separated list.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<AccessToken> ClientCredentialsGrant(string client_id, string client_secret, string scope);

   /// <summary>
   /// Adds a comment to the user's account.
   /// </summary>
   /// <param name="request"> The request object that contains all the information used to create the user comment.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserCommentResponse> CommentOnUser(UserCommentRequest request);

   /// <summary>
   /// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge without logging the user in
   /// </summary>
   /// <param name="request"> An object containing data necessary for completing the authentication ceremony</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebAuthnAssertResponse> CompleteWebAuthnAssertion(WebAuthnLoginRequest request);

   /// <summary>
   /// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge and then login the user in
   /// </summary>
   /// <param name="request"> An object containing data necessary for completing the authentication ceremony</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginResponse> CompleteWebAuthnLogin(WebAuthnLoginRequest request);

   /// <summary>
   /// Complete a WebAuthn registration ceremony by validating the client request and saving the new credential
   /// </summary>
   /// <param name="request"> An object containing data necessary for completing the registration ceremony</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebAuthnRegisterCompleteResponse> CompleteWebAuthnRegistration(WebAuthnRegisterCompleteRequest request);

   /// <summary>
   /// Creates an API key. You can optionally specify a unique Id for the key, if not provided one will be generated.
   /// an API key can only be created with equal or lesser authority. An API key cannot create another API key unless it is granted 
   /// to that API key.
   /// 
   /// If an API key is locked to a tenant, it can only create API Keys for that same tenant.
   /// </summary>
   /// <param name="keyId"> (Optional) The unique Id of the API key. If not provided a secure random Id will be generated.</param>
   /// <param name="request"> The request object that contains all the information needed to create the APIKey.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<APIKeyResponse> CreateAPIKey(Guid? keyId, APIKeyRequest request);

   /// <summary>
   /// Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
   /// </summary>
   /// <param name="applicationId"> (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the application.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> CreateApplication(Guid? applicationId, ApplicationRequest request);

   /// <summary>
   /// Creates a new role for an application. You must specify the Id of the application you are creating the role for.
   /// You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
   /// </summary>
   /// <param name="applicationId"> The Id of the application to create the role on.</param>
   /// <param name="roleId"> (Optional) The Id of the role. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the application role.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> CreateApplicationRole(Guid? applicationId, Guid? roleId, ApplicationRequest request);

   /// <summary>
   /// Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
   /// make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
   /// written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
   /// </summary>
   /// <param name="request"> The request object that contains all the information used to create the audit log entry.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<AuditLogResponse> CreateAuditLog(AuditLogRequest request);

   /// <summary>
   /// Creates a connector.  You can optionally specify an Id for the connector, if not provided one will be generated.
   /// </summary>
   /// <param name="connectorId"> (Optional) The Id for the connector. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the connector.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConnectorResponse> CreateConnector(Guid? connectorId, ConnectorRequest request);

   /// <summary>
   /// Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
   /// </summary>
   /// <param name="consentId"> (Optional) The Id for the consent. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the consent.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConsentResponse> CreateConsent(Guid? consentId, ConsentRequest request);

   /// <summary>
   /// Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
   /// </summary>
   /// <param name="emailTemplateId"> (Optional) The Id for the template. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the email template.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EmailTemplateResponse> CreateEmailTemplate(Guid? emailTemplateId, EmailTemplateRequest request);

   /// <summary>
   /// Creates an Entity. You can optionally specify an Id for the Entity. If not provided one will be generated.
   /// </summary>
   /// <param name="entityId"> (Optional) The Id for the Entity. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the Entity.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityResponse> CreateEntity(Guid? entityId, EntityRequest request);

   /// <summary>
   /// Creates a Entity Type. You can optionally specify an Id for the Entity Type, if not provided one will be generated.
   /// </summary>
   /// <param name="entityTypeId"> (Optional) The Id for the Entity Type. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the Entity Type.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityTypeResponse> CreateEntityType(Guid? entityTypeId, EntityTypeRequest request);

   /// <summary>
   /// Creates a new permission for an entity type. You must specify the Id of the entity type you are creating the permission for.
   /// You can optionally specify an Id for the permission inside the EntityTypePermission object itself, if not provided one will be generated.
   /// </summary>
   /// <param name="entityTypeId"> The Id of the entity type to create the permission on.</param>
   /// <param name="permissionId"> (Optional) The Id of the permission. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the permission.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityTypeResponse> CreateEntityTypePermission(Guid? entityTypeId, Guid? permissionId, EntityTypeRequest request);

   /// <summary>
   /// Creates a family with the user Id in the request as the owner and sole member of the family. You can optionally specify an Id for the
   /// family, if not provided one will be generated.
   /// </summary>
   /// <param name="familyId"> (Optional) The Id for the family. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the family.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FamilyResponse> CreateFamily(Guid? familyId, FamilyRequest request);

   /// <summary>
   /// Creates a form.  You can optionally specify an Id for the form, if not provided one will be generated.
   /// </summary>
   /// <param name="formId"> (Optional) The Id for the form. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the form.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FormResponse> CreateForm(Guid? formId, FormRequest request);

   /// <summary>
   /// Creates a form field.  You can optionally specify an Id for the form, if not provided one will be generated.
   /// </summary>
   /// <param name="fieldId"> (Optional) The Id for the form field. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the form field.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FormFieldResponse> CreateFormField(Guid? fieldId, FormFieldRequest request);

   /// <summary>
   /// Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
   /// </summary>
   /// <param name="groupId"> (Optional) The Id for the group. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the group.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<GroupResponse> CreateGroup(Guid? groupId, GroupRequest request);

   /// <summary>
   /// Creates a member in a group.
   /// </summary>
   /// <param name="request"> The request object that contains all the information used to create the group member(s).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MemberResponse> CreateGroupMembers(MemberRequest request);

   /// <summary>
   /// Creates an IP Access Control List. You can optionally specify an Id on this create request, if one is not provided one will be generated.
   /// </summary>
   /// <param name="accessControlListId"> (Optional) The Id for the IP Access Control List. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the IP Access Control List.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IPAccessControlListResponse> CreateIPAccessControlList(Guid? accessControlListId, IPAccessControlListRequest request);

   /// <summary>
   /// Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
   /// </summary>
   /// <param name="identityProviderId"> (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the identity provider.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderResponse> CreateIdentityProvider(Guid? identityProviderId, IdentityProviderRequest request);

   /// <summary>
   /// Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
   /// </summary>
   /// <param name="lambdaId"> (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the lambda.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LambdaResponse> CreateLambda(Guid? lambdaId, LambdaRequest request);

   /// <summary>
   /// Creates an message template. You can optionally specify an Id for the template, if not provided one will be generated.
   /// </summary>
   /// <param name="messageTemplateId"> (Optional) The Id for the template. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the message template.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessageTemplateResponse> CreateMessageTemplate(Guid? messageTemplateId, MessageTemplateRequest request);

   /// <summary>
   /// Creates a messenger.  You can optionally specify an Id for the messenger, if not provided one will be generated.
   /// </summary>
   /// <param name="messengerId"> (Optional) The Id for the messenger. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the messenger.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessengerResponse> CreateMessenger(Guid? messengerId, MessengerRequest request);

   /// <summary>
   /// Creates a new custom OAuth scope for an application. You must specify the Id of the application you are creating the scope for.
   /// You can optionally specify an Id for the OAuth scope on the URL, if not provided one will be generated.
   /// </summary>
   /// <param name="applicationId"> The Id of the application to create the OAuth scope on.</param>
   /// <param name="scopeId"> (Optional) The Id of the OAuth scope. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the OAuth OAuth scope.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationOAuthScopeResponse> CreateOAuthScope(Guid? applicationId, Guid? scopeId, ApplicationOAuthScopeRequest request);

   /// <summary>
   /// Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
   /// </summary>
   /// <param name="tenantId"> (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the tenant.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TenantResponse> CreateTenant(Guid? tenantId, TenantRequest request);

   /// <summary>
   /// Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
   /// </summary>
   /// <param name="themeId"> (Optional) The Id for the theme. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the theme.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ThemeResponse> CreateTheme(Guid? themeId, ThemeRequest request);

   /// <summary>
   /// Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
   /// </summary>
   /// <param name="userId"> (Optional) The Id for the user. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> CreateUser(Guid? userId, UserRequest request);

   /// <summary>
   /// Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
   /// that the user action can be applied to any user.
   /// </summary>
   /// <param name="userActionId"> (Optional) The Id for the user action. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the user action.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionResponse> CreateUserAction(Guid? userActionId, UserActionRequest request);

   /// <summary>
   /// Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
   /// successfully. Anytime after that the user action reason can be used.
   /// </summary>
   /// <param name="userActionReasonId"> (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the user action reason.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionReasonResponse> CreateUserActionReason(Guid? userActionReasonId, UserActionReasonRequest request);

   /// <summary>
   /// Creates a single User consent.
   /// </summary>
   /// <param name="userConsentId"> (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request that contains the user consent information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserConsentResponse> CreateUserConsent(Guid? userConsentId, UserConsentRequest request);

   /// <summary>
   /// Link an external user from a 3rd party identity provider to a FusionAuth user.
   /// </summary>
   /// <param name="request"> The request object that contains all the information used to link the FusionAuth user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderLinkResponse> CreateUserLink(IdentityProviderLinkRequest request);

   /// <summary>
   /// Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
   /// </summary>
   /// <param name="webhookId"> (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the webhook.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebhookResponse> CreateWebhook(Guid? webhookId, WebhookRequest request);

   /// <summary>
   /// Deactivates the application with the given Id.
   /// </summary>
   /// <param name="applicationId"> The Id of the application to deactivate.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeactivateApplication(Guid? applicationId);

   /// <summary>
   /// Deactivates the FusionAuth Reactor.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeactivateReactor();

   /// <summary>
   /// Deactivates the user with the given Id.
   /// </summary>
   /// <param name="userId"> The Id of the user to deactivate.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeactivateUser(Guid? userId);

   /// <summary>
   /// Deactivates the user action with the given Id.
   /// </summary>
   /// <param name="userActionId"> The Id of the user action to deactivate.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeactivateUserAction(Guid? userActionId);

   /// <summary>
   /// Deactivates the users with the given ids.
   /// </summary>
   /// <param name="userIds"> The ids of the users to deactivate.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   [Obsolete("This method has been renamed to DeactivateUsersByIdsAsync, use that method instead.")]
   ClientResponse<UserDeleteResponse> DeactivateUsers(List<string> userIds);

   /// <summary>
   /// Deactivates the users with the given ids.
   /// </summary>
   /// <param name="userIds"> The ids of the users to deactivate.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserDeleteResponse> DeactivateUsersByIds(List<string> userIds);

   /// <summary>
   /// Deletes the API key for the given Id.
   /// </summary>
   /// <param name="keyId"> The Id of the authentication API key to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteAPIKey(Guid? keyId);

   /// <summary>
   /// Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
   /// delete the application, any registrations for that application, metrics and reports for the application, all the
   /// roles for the application, and any other data associated with the application. This operation could take a very
   /// long time, depending on the amount of data in your database.
   /// </summary>
   /// <param name="applicationId"> The Id of the application to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteApplication(Guid? applicationId);

   /// <summary>
   /// Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
   /// permanently removes the given role from all users that had it.
   /// </summary>
   /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
   /// <param name="roleId"> The Id of the role to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteApplicationRole(Guid? applicationId, Guid? roleId);

   /// <summary>
   /// Deletes the connector for the given Id.
   /// </summary>
   /// <param name="connectorId"> The Id of the connector to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteConnector(Guid? connectorId);

   /// <summary>
   /// Deletes the consent for the given Id.
   /// </summary>
   /// <param name="consentId"> The Id of the consent to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteConsent(Guid? consentId);

   /// <summary>
   /// Deletes the email template for the given Id.
   /// </summary>
   /// <param name="emailTemplateId"> The Id of the email template to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteEmailTemplate(Guid? emailTemplateId);

   /// <summary>
   /// Deletes the Entity for the given Id.
   /// </summary>
   /// <param name="entityId"> The Id of the Entity to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteEntity(Guid? entityId);

   /// <summary>
   /// Deletes an Entity Grant for the given User or Entity.
   /// </summary>
   /// <param name="entityId"> The Id of the Entity that the Entity Grant is being deleted for.</param>
   /// <param name="recipientEntityId"> (Optional) The Id of the Entity that the Entity Grant is for.</param>
   /// <param name="userId"> (Optional) The Id of the User that the Entity Grant is for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteEntityGrant(Guid? entityId, Guid? recipientEntityId, Guid? userId);

   /// <summary>
   /// Deletes the Entity Type for the given Id.
   /// </summary>
   /// <param name="entityTypeId"> The Id of the Entity Type to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteEntityType(Guid? entityTypeId);

   /// <summary>
   /// Hard deletes a permission. This is a dangerous operation and should not be used in most circumstances. This
   /// permanently removes the given permission from all grants that had it.
   /// </summary>
   /// <param name="entityTypeId"> The Id of the entityType the the permission belongs to.</param>
   /// <param name="permissionId"> The Id of the permission to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteEntityTypePermission(Guid? entityTypeId, Guid? permissionId);

   /// <summary>
   /// Deletes the form for the given Id.
   /// </summary>
   /// <param name="formId"> The Id of the form to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteForm(Guid? formId);

   /// <summary>
   /// Deletes the form field for the given Id.
   /// </summary>
   /// <param name="fieldId"> The Id of the form field to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteFormField(Guid? fieldId);

   /// <summary>
   /// Deletes the group for the given Id.
   /// </summary>
   /// <param name="groupId"> The Id of the group to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteGroup(Guid? groupId);

   /// <summary>
   /// Removes users as members of a group.
   /// </summary>
   /// <param name="request"> The member request that contains all the information used to remove members to the group.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteGroupMembers(MemberDeleteRequest request);

   /// <summary>
   /// Deletes the IP Access Control List for the given Id.
   /// </summary>
   /// <param name="ipAccessControlListId"> The Id of the IP Access Control List to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteIPAccessControlList(Guid? ipAccessControlListId);

   /// <summary>
   /// Deletes the identity provider for the given Id.
   /// </summary>
   /// <param name="identityProviderId"> The Id of the identity provider to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteIdentityProvider(Guid? identityProviderId);

   /// <summary>
   /// Deletes the key for the given Id.
   /// </summary>
   /// <param name="keyId"> The Id of the key to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteKey(Guid? keyId);

   /// <summary>
   /// Deletes the lambda for the given Id.
   /// </summary>
   /// <param name="lambdaId"> The Id of the lambda to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteLambda(Guid? lambdaId);

   /// <summary>
   /// Deletes the message template for the given Id.
   /// </summary>
   /// <param name="messageTemplateId"> The Id of the message template to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteMessageTemplate(Guid? messageTemplateId);

   /// <summary>
   /// Deletes the messenger for the given Id.
   /// </summary>
   /// <param name="messengerId"> The Id of the messenger to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteMessenger(Guid? messengerId);

   /// <summary>
   /// Hard deletes a custom OAuth scope. This action will cause tokens that contain the deleted scope to be rejected.
   /// OAuth workflows that are still requesting the deleted OAuth scope may fail depending on the application's unknown scope policy.
   /// </summary>
   /// <param name="applicationId"> The Id of the application that the OAuth scope belongs to.</param>
   /// <param name="scopeId"> The Id of the OAuth scope to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteOAuthScope(Guid? applicationId, Guid? scopeId);

   /// <summary>
   /// Deletes the user registration for the given user and application.
   /// </summary>
   /// <param name="userId"> The Id of the user whose registration is being deleted.</param>
   /// <param name="applicationId"> The Id of the application to remove the registration for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteRegistration(Guid? userId, Guid? applicationId);

   /// <summary>
   /// Deletes the user registration for the given user and application along with the given JSON body that contains the event information.
   /// </summary>
   /// <param name="userId"> The Id of the user whose registration is being deleted.</param>
   /// <param name="applicationId"> The Id of the application to remove the registration for.</param>
   /// <param name="request"> The request body that contains the event information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteRegistrationWithRequest(Guid? userId, Guid? applicationId, RegistrationDeleteRequest request);

   /// <summary>
   /// Deletes the tenant based on the given Id on the URL. This permanently deletes all information, metrics, reports and data associated
   /// with the tenant and everything under the tenant (applications, users, etc).
   /// </summary>
   /// <param name="tenantId"> The Id of the tenant to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteTenant(Guid? tenantId);

   /// <summary>
   /// Deletes the tenant for the given Id asynchronously.
   /// This method is helpful if you do not want to wait for the delete operation to complete.
   /// </summary>
   /// <param name="tenantId"> The Id of the tenant to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteTenantAsync(Guid? tenantId);

   /// <summary>
   /// Deletes the tenant based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
   /// with the tenant and everything under the tenant (applications, users, etc).
   /// </summary>
   /// <param name="tenantId"> The Id of the tenant to delete.</param>
   /// <param name="request"> The request object that contains all the information used to delete the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteTenantWithRequest(Guid? tenantId, TenantDeleteRequest request);

   /// <summary>
   /// Deletes the theme for the given Id.
   /// </summary>
   /// <param name="themeId"> The Id of the theme to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteTheme(Guid? themeId);

   /// <summary>
   /// Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
   /// with the user.
   /// </summary>
   /// <param name="userId"> The Id of the user to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteUser(Guid? userId);

   /// <summary>
   /// Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
   /// the action being applied to any users.
   /// </summary>
   /// <param name="userActionId"> The Id of the user action to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteUserAction(Guid? userActionId);

   /// <summary>
   /// Deletes the user action reason for the given Id.
   /// </summary>
   /// <param name="userActionReasonId"> The Id of the user action reason to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteUserActionReason(Guid? userActionReasonId);

   /// <summary>
   /// Remove an existing link that has been made from a 3rd party identity provider to a FusionAuth user.
   /// </summary>
   /// <param name="identityProviderId"> The unique Id of the identity provider.</param>
   /// <param name="identityProviderUserId"> The unique Id of the user in the 3rd party identity provider to unlink.</param>
   /// <param name="userId"> The unique Id of the FusionAuth user to unlink.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderLinkResponse> DeleteUserLink(Guid? identityProviderId, string identityProviderUserId, Guid? userId);

   /// <summary>
   /// Deletes the user based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
   /// with the user.
   /// </summary>
   /// <param name="userId"> The Id of the user to delete (required).</param>
   /// <param name="request"> The request object that contains all the information used to delete the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteUserWithRequest(Guid? userId, UserDeleteSingleRequest request);

   /// <summary>
   /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
   /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
   /// 
   /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
   /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
   /// </summary>
   /// <param name="request"> The UserDeleteRequest.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   [Obsolete("This method has been renamed to DeleteUsersByQueryAsync, use that method instead.")]
   ClientResponse<UserDeleteResponse> DeleteUsers(UserDeleteRequest request);

   /// <summary>
   /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
   /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
   /// 
   /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
   /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
   /// </summary>
   /// <param name="request"> The UserDeleteRequest.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserDeleteResponse> DeleteUsersByQuery(UserDeleteRequest request);

   /// <summary>
   /// Deletes the WebAuthn credential for the given Id.
   /// </summary>
   /// <param name="id"> The Id of the WebAuthn credential to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteWebAuthnCredential(Guid? id);

   /// <summary>
   /// Deletes the webhook for the given Id.
   /// </summary>
   /// <param name="webhookId"> The Id of the webhook to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DeleteWebhook(Guid? webhookId);

   /// <summary>
   /// Disable two-factor authentication for a user.
   /// </summary>
   /// <param name="userId"> The Id of the User for which you're disabling two-factor authentication.</param>
   /// <param name="methodId"> The two-factor method identifier you wish to disable</param>
   /// <param name="code"> The two-factor code used verify the the caller knows the two-factor secret.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DisableTwoFactor(Guid? userId, string methodId, string code);

   /// <summary>
   /// Disable two-factor authentication for a user using a JSON body rather than URL parameters.
   /// </summary>
   /// <param name="userId"> The Id of the User for which you're disabling two-factor authentication.</param>
   /// <param name="request"> The request information that contains the code and methodId along with any event information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> DisableTwoFactorWithRequest(Guid? userId, TwoFactorDisableRequest request);

   /// <summary>
   /// Enable two-factor authentication for a user.
   /// </summary>
   /// <param name="userId"> The Id of the user to enable two-factor authentication.</param>
   /// <param name="request"> The two-factor enable request information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TwoFactorResponse> EnableTwoFactor(Guid? userId, TwoFactorRequest request);

   /// <summary>
   /// Exchanges an OAuth authorization code for an access token.
   /// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
   /// </summary>
   /// <param name="code"> The authorization code returned on the /oauth2/authorize response.</param>
   /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
   /// <param name="client_secret"> (Optional) The client secret. This value will be required if client authentication is enabled.</param>
   /// <param name="redirect_uri"> The URI to redirect to upon a successful request.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<AccessToken> ExchangeOAuthCodeForAccessToken(string code, string client_id, string client_secret, string redirect_uri);

   /// <summary>
   /// Exchanges an OAuth authorization code and code_verifier for an access token.
   /// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint and a code_verifier for an access token.
   /// </summary>
   /// <param name="code"> The authorization code returned on the /oauth2/authorize response.</param>
   /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
   /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
   /// <param name="redirect_uri"> The URI to redirect to upon a successful request.</param>
   /// <param name="code_verifier"> The random string generated previously. Will be compared with the code_challenge sent previously, which allows the OAuth provider to authenticate your app.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<AccessToken> ExchangeOAuthCodeForAccessTokenUsingPKCE(string code, string client_id, string client_secret, string redirect_uri, string code_verifier);

   /// <summary>
   /// Exchange a Refresh Token for an Access Token.
   /// If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
   /// </summary>
   /// <param name="refresh_token"> The refresh token that you would like to use to exchange for an access token.</param>
   /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
   /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
   /// <param name="scope"> (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.</param>
   /// <param name="user_code"> (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<AccessToken> ExchangeRefreshTokenForAccessToken(string refresh_token, string client_id, string client_secret, string scope, string user_code);

   /// <summary>
   /// Exchange a refresh token for a new JWT.
   /// </summary>
   /// <param name="request"> The refresh request.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<JWTRefreshResponse> ExchangeRefreshTokenForJWT(RefreshRequest request);

   /// <summary>
   /// Exchange User Credentials for a Token.
   /// If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
   /// </summary>
   /// <param name="username"> The login identifier of the user. The login identifier can be either the email or the username.</param>
   /// <param name="password"> The user’s password.</param>
   /// <param name="client_id"> (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
    /// This parameter is optional when Basic Authorization is used to authenticate this request.</param>
   /// <param name="client_secret"> (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.</param>
   /// <param name="scope"> (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.</param>
   /// <param name="user_code"> (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<AccessToken> ExchangeUserCredentialsForAccessToken(string username, string password, string client_id, string client_secret, string scope, string user_code);

   /// <summary>
   /// Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
   /// </summary>
   /// <param name="request"> The request that contains the information about the user so that they can be emailed.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ForgotPasswordResponse> ForgotPassword(ForgotPasswordRequest request);

   /// <summary>
   /// Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
   /// email to the User. This API may be used to collect the verificationId for use with a third party system.
   /// </summary>
   /// <param name="email"> The email address of the user that needs a new verification email.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<VerifyEmailResponse> GenerateEmailVerificationId(string email);

   /// <summary>
   /// Generate a new RSA or EC key pair or an HMAC secret.
   /// </summary>
   /// <param name="keyId"> (Optional) The Id for the key. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the key.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<KeyResponse> GenerateKey(Guid? keyId, KeyRequest request);

   /// <summary>
   /// Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
   /// email to the User. This API may be used to collect the verificationId for use with a third party system.
   /// </summary>
   /// <param name="email"> The email address of the user that needs a new verification email.</param>
   /// <param name="applicationId"> The Id of the application to be verified.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<VerifyRegistrationResponse> GenerateRegistrationVerificationId(string email, Guid? applicationId);

   /// <summary>
   /// Generate two-factor recovery codes for a user. Generating two-factor recovery codes will invalidate any existing recovery codes. 
   /// </summary>
   /// <param name="userId"> The Id of the user to generate new Two Factor recovery codes.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TwoFactorRecoveryCodeResponse> GenerateTwoFactorRecoveryCodes(Guid? userId);

   /// <summary>
   /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
   /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
   /// application such as Google Authenticator.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<SecretResponse> GenerateTwoFactorSecret();

   /// <summary>
   /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
   /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
   /// application such as Google Authenticator.
   /// </summary>
   /// <param name="encodedJWT"> The encoded JWT (access token).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<SecretResponse> GenerateTwoFactorSecretUsingJWT(string encodedJWT);

   /// <summary>
   /// Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
   /// login systems.
   /// </summary>
   /// <param name="request"> The third-party login request that contains information from the third-party login
    /// providers that FusionAuth uses to reconcile the user's account.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginResponse> IdentityProviderLogin(IdentityProviderLoginRequest request);

   /// <summary>
   /// Import an existing RSA or EC key pair or an HMAC secret.
   /// </summary>
   /// <param name="keyId"> (Optional) The Id for the key. If not provided a secure random UUID will be generated.</param>
   /// <param name="request"> The request object that contains all the information used to create the key.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<KeyResponse> ImportKey(Guid? keyId, KeyRequest request);

   /// <summary>
   /// Bulk imports refresh tokens. This request performs minimal validation and runs batch inserts of refresh tokens with the
   /// expectation that each token represents a user that already exists and is registered for the corresponding FusionAuth
   /// Application. This is done to increases the insert performance.
   /// 
   /// Therefore, if you encounter an error due to a database key violation, the response will likely offer a generic
   /// explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
   /// body with specific validation errors. This will slow the request down but will allow you to identify the cause of
   /// the failure. See the validateDbConstraints request parameter.
   /// </summary>
   /// <param name="request"> The request that contains all the information about all the refresh tokens to import.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> ImportRefreshTokens(RefreshTokenImportRequest request);

   /// <summary>
   /// Bulk imports users. This request performs minimal validation and runs batch inserts of users with the expectation
   /// that each user does not yet exist and each registration corresponds to an existing FusionAuth Application. This is done to
   /// increases the insert performance.
   /// 
   /// Therefore, if you encounter an error due to a database key violation, the response will likely offer
   /// a generic explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
   /// body with specific validation errors. This will slow the request down but will allow you to identify the cause of the failure. See
   /// the validateDbConstraints request parameter.
   /// </summary>
   /// <param name="request"> The request that contains all the information about all the users to import.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> ImportUsers(ImportRequest request);

   /// <summary>
   /// Import a WebAuthn credential
   /// </summary>
   /// <param name="request"> An object containing data necessary for importing the credential</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> ImportWebAuthnCredential(WebAuthnCredentialImportRequest request);

   /// <summary>
   /// Inspect an access token issued as the result of the User based grant such as the Authorization Code Grant, Implicit Grant, the User Credentials Grant or the Refresh Grant.
   /// </summary>
   /// <param name="client_id"> The unique client identifier. The client Id is the Id of the FusionAuth Application for which this token was generated.</param>
   /// <param name="token"> The access token returned by this OAuth provider as the result of a successful client credentials grant.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IntrospectResponse> IntrospectAccessToken(string client_id, string token);

   /// <summary>
   /// Inspect an access token issued as the result of the Client Credentials Grant.
   /// </summary>
   /// <param name="token"> The access token returned by this OAuth provider as the result of a successful client credentials grant.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IntrospectResponse> IntrospectClientCredentialsAccessToken(string token);

   /// <summary>
   /// Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
   /// access token is properly signed and not expired.
   /// <p>
   /// This API may be used in an SSO configuration to issue new tokens for another application after the user has
   /// obtained a valid token from authentication.
   /// </summary>
   /// <param name="applicationId"> The Application Id for which you are requesting a new access token be issued.</param>
   /// <param name="encodedJWT"> The encoded JWT (access token).</param>
   /// <param name="refreshToken"> (Optional) An existing refresh token used to request a refresh token in addition to a JWT in the response.
    /// <p>The target application represented by the applicationId request parameter must have refresh
    /// tokens enabled in order to receive a refresh token in the response.</p></param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IssueResponse> IssueJWT(Guid? applicationId, string encodedJWT, string refreshToken);

   /// <summary>
   /// Authenticates a user to FusionAuth. 
   /// 
   /// This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
   /// </summary>
   /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginResponse> Login(LoginRequest request);

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
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginResponse> LoginPing(Guid? userId, Guid? applicationId, string callerIPAddress);

   /// <summary>
   /// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
   /// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
   /// application where they no longer have a session. This helps correctly track login counts, times and helps with
   /// reporting.
   /// </summary>
   /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginResponse> LoginPingWithRequest(LoginPingRequest request);

   /// <summary>
   /// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
   /// client and revoke the refresh token stored. This API does nothing if the request does not contain an access
   /// token or refresh token cookies.
   /// </summary>
   /// <param name="global"> When this value is set to true all the refresh tokens issued to the owner of the
    /// provided token will be revoked.</param>
   /// <param name="refreshToken"> (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
    /// If provided this takes precedence over the cookie.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> Logout(bool? global, string refreshToken);

   /// <summary>
   /// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
   /// client and revoke the refresh token stored. This API takes the refresh token in the JSON body.
   /// </summary>
   /// <param name="request"> The request object that contains all the information used to logout the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> LogoutWithRequest(LogoutRequest request);

   /// <summary>
   /// Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
   /// by a registered identity provider. A 404 indicates the domain is not managed.
   /// </summary>
   /// <param name="domain"> The domain or email address to lookup.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LookupResponse> LookupIdentityProvider(string domain);

   /// <summary>
   /// Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
   /// action.
   /// </summary>
   /// <param name="actionId"> The Id of the action to modify. This is technically the user action log id.</param>
   /// <param name="request"> The request that contains all the information about the modification.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ActionResponse> ModifyAction(Guid? actionId, ActionRequest request);

   /// <summary>
   /// Complete a login request using a passwordless code
   /// </summary>
   /// <param name="request"> The passwordless login request that contains all the information used to complete login.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginResponse> PasswordlessLogin(PasswordlessLoginRequest request);

   /// <summary>
   /// Updates an authentication API key by given id
   /// </summary>
   /// <param name="keyId"> The Id of the authentication key. If not provided a secure random api key will be generated.</param>
   /// <param name="request"> The request object that contains all the information needed to create the APIKey.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<APIKeyResponse> PatchAPIKey(Guid? keyId, APIKeyRequest request);

   /// <summary>
   /// Updates, via PATCH, the application with the given Id.
   /// </summary>
   /// <param name="applicationId"> The Id of the application to update.</param>
   /// <param name="request"> The request that contains just the new application information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> PatchApplication(Guid? applicationId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the application role with the given Id for the application.
   /// </summary>
   /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
   /// <param name="roleId"> The Id of the role to update.</param>
   /// <param name="request"> The request that contains just the new role information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> PatchApplicationRole(Guid? applicationId, Guid? roleId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the connector with the given Id.
   /// </summary>
   /// <param name="connectorId"> The Id of the connector to update.</param>
   /// <param name="request"> The request that contains just the new connector information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConnectorResponse> PatchConnector(Guid? connectorId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the consent with the given Id.
   /// </summary>
   /// <param name="consentId"> The Id of the consent to update.</param>
   /// <param name="request"> The request that contains just the new consent information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConsentResponse> PatchConsent(Guid? consentId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the email template with the given Id.
   /// </summary>
   /// <param name="emailTemplateId"> The Id of the email template to update.</param>
   /// <param name="request"> The request that contains just the new email template information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EmailTemplateResponse> PatchEmailTemplate(Guid? emailTemplateId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the Entity Type with the given Id.
   /// </summary>
   /// <param name="entityTypeId"> The Id of the Entity Type to update.</param>
   /// <param name="request"> The request that contains just the new Entity Type information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityTypeResponse> PatchEntityType(Guid? entityTypeId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the group with the given Id.
   /// </summary>
   /// <param name="groupId"> The Id of the group to update.</param>
   /// <param name="request"> The request that contains just the new group information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<GroupResponse> PatchGroup(Guid? groupId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the identity provider with the given Id.
   /// </summary>
   /// <param name="identityProviderId"> The Id of the identity provider to update.</param>
   /// <param name="request"> The request object that contains just the updated identity provider information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderResponse> PatchIdentityProvider(Guid? identityProviderId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the available integrations.
   /// </summary>
   /// <param name="request"> The request that contains just the new integration information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IntegrationResponse> PatchIntegrations(IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the lambda with the given Id.
   /// </summary>
   /// <param name="lambdaId"> The Id of the lambda to update.</param>
   /// <param name="request"> The request that contains just the new lambda information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LambdaResponse> PatchLambda(Guid? lambdaId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the message template with the given Id.
   /// </summary>
   /// <param name="messageTemplateId"> The Id of the message template to update.</param>
   /// <param name="request"> The request that contains just the new message template information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessageTemplateResponse> PatchMessageTemplate(Guid? messageTemplateId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the messenger with the given Id.
   /// </summary>
   /// <param name="messengerId"> The Id of the messenger to update.</param>
   /// <param name="request"> The request that contains just the new messenger information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessengerResponse> PatchMessenger(Guid? messengerId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the custom OAuth scope with the given Id for the application.
   /// </summary>
   /// <param name="applicationId"> The Id of the application that the OAuth scope belongs to.</param>
   /// <param name="scopeId"> The Id of the OAuth scope to update.</param>
   /// <param name="request"> The request that contains just the new OAuth scope information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationOAuthScopeResponse> PatchOAuthScope(Guid? applicationId, Guid? scopeId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the registration for the user with the given Id and the application defined in the request.
   /// </summary>
   /// <param name="userId"> The Id of the user whose registration is going to be updated.</param>
   /// <param name="request"> The request that contains just the new registration information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RegistrationResponse> PatchRegistration(Guid? userId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the system configuration.
   /// </summary>
   /// <param name="request"> The request that contains just the new system configuration information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<SystemConfigurationResponse> PatchSystemConfiguration(IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the tenant with the given Id.
   /// </summary>
   /// <param name="tenantId"> The Id of the tenant to update.</param>
   /// <param name="request"> The request that contains just the new tenant information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TenantResponse> PatchTenant(Guid? tenantId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the theme with the given Id.
   /// </summary>
   /// <param name="themeId"> The Id of the theme to update.</param>
   /// <param name="request"> The request that contains just the new theme information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ThemeResponse> PatchTheme(Guid? themeId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the user with the given Id.
   /// </summary>
   /// <param name="userId"> The Id of the user to update.</param>
   /// <param name="request"> The request that contains just the new user information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> PatchUser(Guid? userId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the user action with the given Id.
   /// </summary>
   /// <param name="userActionId"> The Id of the user action to update.</param>
   /// <param name="request"> The request that contains just the new user action information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionResponse> PatchUserAction(Guid? userActionId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, the user action reason with the given Id.
   /// </summary>
   /// <param name="userActionReasonId"> The Id of the user action reason to update.</param>
   /// <param name="request"> The request that contains just the new user action reason information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionReasonResponse> PatchUserActionReason(Guid? userActionReasonId, IDictionary<string, object> request);

   /// <summary>
   /// Updates, via PATCH, a single User consent by Id.
   /// </summary>
   /// <param name="userConsentId"> The User Consent Id</param>
   /// <param name="request"> The request that contains just the new user consent information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserConsentResponse> PatchUserConsent(Guid? userConsentId, IDictionary<string, object> request);

   /// <summary>
   /// Reactivates the application with the given Id.
   /// </summary>
   /// <param name="applicationId"> The Id of the application to reactivate.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> ReactivateApplication(Guid? applicationId);

   /// <summary>
   /// Reactivates the user with the given Id.
   /// </summary>
   /// <param name="userId"> The Id of the user to reactivate.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> ReactivateUser(Guid? userId);

   /// <summary>
   /// Reactivates the user action with the given Id.
   /// </summary>
   /// <param name="userActionId"> The Id of the user action to reactivate.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionResponse> ReactivateUserAction(Guid? userActionId);

   /// <summary>
   /// Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
   /// </summary>
   /// <param name="request"> The reconcile request that contains the data to reconcile the User.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginResponse> ReconcileJWT(IdentityProviderLoginRequest request);

   /// <summary>
   /// Request a refresh of the Entity search index. This API is not generally necessary and the search index will become consistent in a
   /// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
   /// if you are using the Search API or Delete Tenant API immediately following a Entity Create etc, you may wish to request a refresh to
   ///  ensure the index immediately current before making a query request to the search index.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RefreshEntitySearchIndex();

   /// <summary>
   /// Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
   /// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be 
   /// if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
   ///  ensure the index immediately current before making a query request to the search index.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RefreshUserSearchIndex();

   /// <summary>
   /// Regenerates any keys that are used by the FusionAuth Reactor.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RegenerateReactorKeys();

   /// <summary>
   /// Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
   /// will create the user as well as register them for the application. This is called a Full Registration. However, if
   /// you only provide the UserRegistration object, then the user must already exist and they will be registered for the
   /// application. The user Id can also be provided and it will either be used to look up an existing user or it will be
   /// used for the newly created User.
   /// </summary>
   /// <param name="userId"> (Optional) The Id of the user being registered for the application and optionally created.</param>
   /// <param name="request"> The request that optionally contains the User and must contain the UserRegistration.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RegistrationResponse> Register(Guid? userId, RegistrationRequest request);

   /// <summary>
   /// Requests Elasticsearch to delete and rebuild the index for FusionAuth users or entities. Be very careful when running this request as it will 
   /// increase the CPU and I/O load on your database until the operation completes. Generally speaking you do not ever need to run this operation unless 
   /// instructed by FusionAuth support, or if you are migrating a database another system and you are not brining along the Elasticsearch index. 
   /// 
   /// You have been warned.
   /// </summary>
   /// <param name="request"> The request that contains the index name.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> Reindex(ReindexRequest request);

   /// <summary>
   /// Removes a user from the family with the given id.
   /// </summary>
   /// <param name="familyId"> The Id of the family to remove the user from.</param>
   /// <param name="userId"> The Id of the user to remove from the family.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RemoveUserFromFamily(Guid? familyId, Guid? userId);

   /// <summary>
   /// Re-sends the verification email to the user.
   /// </summary>
   /// <param name="email"> The email address of the user that needs a new verification email.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<VerifyEmailResponse> ResendEmailVerification(string email);

   /// <summary>
   /// Re-sends the verification email to the user. If the Application has configured a specific email template this will be used
   /// instead of the tenant configuration.
   /// </summary>
   /// <param name="applicationId"> The unique Application Id to used to resolve an application specific email template.</param>
   /// <param name="email"> The email address of the user that needs a new verification email.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<VerifyEmailResponse> ResendEmailVerificationWithApplicationTemplate(Guid? applicationId, string email);

   /// <summary>
   /// Re-sends the application registration verification email to the user.
   /// </summary>
   /// <param name="email"> The email address of the user that needs a new verification email.</param>
   /// <param name="applicationId"> The Id of the application to be verified.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<VerifyRegistrationResponse> ResendRegistrationVerification(string email, Guid? applicationId);

   /// <summary>
   /// Retrieves an authentication API key for the given id
   /// </summary>
   /// <param name="keyId"> The Id of the API key to retrieve.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<APIKeyResponse> RetrieveAPIKey(Guid? keyId);

   /// <summary>
   /// Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
   /// </summary>
   /// <param name="actionId"> The Id of the action to retrieve.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ActionResponse> RetrieveAction(Guid? actionId);

   /// <summary>
   /// Retrieves all the actions for the user with the given Id. This will return all time based actions that are active,
   /// and inactive as well as non-time based actions.
   /// </summary>
   /// <param name="userId"> The Id of the user to fetch the actions for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ActionResponse> RetrieveActions(Guid? userId);

   /// <summary>
   /// Retrieves all the actions for the user with the given Id that are currently preventing the User from logging in.
   /// </summary>
   /// <param name="userId"> The Id of the user to fetch the actions for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ActionResponse> RetrieveActionsPreventingLogin(Guid? userId);

   /// <summary>
   /// Retrieves all the actions for the user with the given Id that are currently active.
   /// An active action means one that is time based and has not been canceled, and has not ended.
   /// </summary>
   /// <param name="userId"> The Id of the user to fetch the actions for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ActionResponse> RetrieveActiveActions(Guid? userId);

   /// <summary>
   /// Retrieves the application for the given Id or all the applications if the Id is null.
   /// </summary>
   /// <param name="applicationId"> (Optional) The application id.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> RetrieveApplication(Guid? applicationId);

   /// <summary>
   /// Retrieves all the applications.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> RetrieveApplications();

   /// <summary>
   /// Retrieves a single audit log for the given Id.
   /// </summary>
   /// <param name="auditLogId"> The Id of the audit log to retrieve.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<AuditLogResponse> RetrieveAuditLog(int? auditLogId);

   /// <summary>
   /// Retrieves the connector with the given Id.
   /// </summary>
   /// <param name="connectorId"> The Id of the connector.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConnectorResponse> RetrieveConnector(Guid? connectorId);

   /// <summary>
   /// Retrieves all the connectors.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConnectorResponse> RetrieveConnectors();

   /// <summary>
   /// Retrieves the Consent for the given Id.
   /// </summary>
   /// <param name="consentId"> The Id of the consent.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConsentResponse> RetrieveConsent(Guid? consentId);

   /// <summary>
   /// Retrieves all the consent.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConsentResponse> RetrieveConsents();

   /// <summary>
   /// Retrieves the daily active user report between the two instants. If you specify an application id, it will only
   /// return the daily active counts for that application.
   /// </summary>
   /// <param name="applicationId"> (Optional) The application id.</param>
   /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
   /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<DailyActiveUserReportResponse> RetrieveDailyActiveReport(Guid? applicationId, long? start, long? end);

   /// <summary>
   /// Retrieves the email template for the given Id. If you don't specify the id, this will return all the email templates.
   /// </summary>
   /// <param name="emailTemplateId"> (Optional) The Id of the email template.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EmailTemplateResponse> RetrieveEmailTemplate(Guid? emailTemplateId);

   /// <summary>
   /// Creates a preview of the email template provided in the request. This allows you to preview an email template that
   /// hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
   /// will create the preview based on whatever is given.
   /// </summary>
   /// <param name="request"> The request that contains the email template and optionally a locale to render it in.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PreviewResponse> RetrieveEmailTemplatePreview(PreviewRequest request);

   /// <summary>
   /// Retrieves all the email templates.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EmailTemplateResponse> RetrieveEmailTemplates();

   /// <summary>
   /// Retrieves the Entity for the given Id.
   /// </summary>
   /// <param name="entityId"> The Id of the Entity.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityResponse> RetrieveEntity(Guid? entityId);

   /// <summary>
   /// Retrieves an Entity Grant for the given Entity and User/Entity.
   /// </summary>
   /// <param name="entityId"> The Id of the Entity.</param>
   /// <param name="recipientEntityId"> (Optional) The Id of the Entity that the Entity Grant is for.</param>
   /// <param name="userId"> (Optional) The Id of the User that the Entity Grant is for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityGrantResponse> RetrieveEntityGrant(Guid? entityId, Guid? recipientEntityId, Guid? userId);

   /// <summary>
   /// Retrieves the Entity Type for the given Id.
   /// </summary>
   /// <param name="entityTypeId"> The Id of the Entity Type.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityTypeResponse> RetrieveEntityType(Guid? entityTypeId);

   /// <summary>
   /// Retrieves all the Entity Types.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityTypeResponse> RetrieveEntityTypes();

   /// <summary>
   /// Retrieves a single event log for the given Id.
   /// </summary>
   /// <param name="eventLogId"> The Id of the event log to retrieve.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EventLogResponse> RetrieveEventLog(int? eventLogId);

   /// <summary>
   /// Retrieves all the families that a user belongs to.
   /// </summary>
   /// <param name="userId"> The User's id</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FamilyResponse> RetrieveFamilies(Guid? userId);

   /// <summary>
   /// Retrieves all the members of a family by the unique Family Id.
   /// </summary>
   /// <param name="familyId"> The unique Id of the Family.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FamilyResponse> RetrieveFamilyMembersByFamilyId(Guid? familyId);

   /// <summary>
   /// Retrieves the form with the given Id.
   /// </summary>
   /// <param name="formId"> The Id of the form.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FormResponse> RetrieveForm(Guid? formId);

   /// <summary>
   /// Retrieves the form field with the given Id.
   /// </summary>
   /// <param name="fieldId"> The Id of the form field.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FormFieldResponse> RetrieveFormField(Guid? fieldId);

   /// <summary>
   /// Retrieves all the forms fields
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FormFieldResponse> RetrieveFormFields();

   /// <summary>
   /// Retrieves all the forms.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FormResponse> RetrieveForms();

   /// <summary>
   /// Retrieves the group for the given Id.
   /// </summary>
   /// <param name="groupId"> The Id of the group.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<GroupResponse> RetrieveGroup(Guid? groupId);

   /// <summary>
   /// Retrieves all the groups.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<GroupResponse> RetrieveGroups();

   /// <summary>
   /// Retrieves the IP Access Control List with the given Id.
   /// </summary>
   /// <param name="ipAccessControlListId"> The Id of the IP Access Control List.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IPAccessControlListResponse> RetrieveIPAccessControlList(Guid? ipAccessControlListId);

   /// <summary>
   /// Retrieves the identity provider for the given Id or all the identity providers if the Id is null.
   /// </summary>
   /// <param name="identityProviderId"> The identity provider Id.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderResponse> RetrieveIdentityProvider(Guid? identityProviderId);

   /// <summary>
   /// Retrieves one or more identity provider for the given type. For types such as Google, Facebook, Twitter and LinkedIn, only a single 
   /// identity provider can exist. For types such as OpenID Connect and SAMLv2 more than one identity provider can be configured so this request 
   /// may return multiple identity providers.
   /// </summary>
   /// <param name="type"> The type of the identity provider.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderResponse> RetrieveIdentityProviderByType(IdentityProviderType type);

   /// <summary>
   /// Retrieves all the identity providers.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderResponse> RetrieveIdentityProviders();

   /// <summary>
   /// Retrieves all the actions for the user with the given Id that are currently inactive.
   /// An inactive action means one that is time based and has been canceled or has expired, or is not time based.
   /// </summary>
   /// <param name="userId"> The Id of the user to fetch the actions for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ActionResponse> RetrieveInactiveActions(Guid? userId);

   /// <summary>
   /// Retrieves all the applications that are currently inactive.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> RetrieveInactiveApplications();

   /// <summary>
   /// Retrieves all the user actions that are currently inactive.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionResponse> RetrieveInactiveUserActions();

   /// <summary>
   /// Retrieves the available integrations.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IntegrationResponse> RetrieveIntegration();

   /// <summary>
   /// Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
   /// </summary>
   /// <param name="keyId"> The Id of the public key (kid).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PublicKeyResponse> RetrieveJWTPublicKey(string keyId);

   /// <summary>
   /// Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
   /// </summary>
   /// <param name="applicationId"> The Id of the Application for which this key is used.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PublicKeyResponse> RetrieveJWTPublicKeyByApplicationId(string applicationId);

   /// <summary>
   /// Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PublicKeyResponse> RetrieveJWTPublicKeys();

   /// <summary>
   /// Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<JWKSResponse> RetrieveJsonWebKeySet();

   /// <summary>
   /// Retrieves the key for the given Id.
   /// </summary>
   /// <param name="keyId"> The Id of the key.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<KeyResponse> RetrieveKey(Guid? keyId);

   /// <summary>
   /// Retrieves all the keys.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<KeyResponse> RetrieveKeys();

   /// <summary>
   /// Retrieves the lambda for the given Id.
   /// </summary>
   /// <param name="lambdaId"> The Id of the lambda.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LambdaResponse> RetrieveLambda(Guid? lambdaId);

   /// <summary>
   /// Retrieves all the lambdas.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LambdaResponse> RetrieveLambdas();

   /// <summary>
   /// Retrieves all the lambdas for the provided type.
   /// </summary>
   /// <param name="type"> The type of the lambda to return.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LambdaResponse> RetrieveLambdasByType(LambdaType type);

   /// <summary>
   /// Retrieves the login report between the two instants. If you specify an application id, it will only return the
   /// login counts for that application.
   /// </summary>
   /// <param name="applicationId"> (Optional) The application id.</param>
   /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
   /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginReportResponse> RetrieveLoginReport(Guid? applicationId, long? start, long? end);

   /// <summary>
   /// Retrieves the message template for the given Id. If you don't specify the id, this will return all the message templates.
   /// </summary>
   /// <param name="messageTemplateId"> (Optional) The Id of the message template.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessageTemplateResponse> RetrieveMessageTemplate(Guid? messageTemplateId);

   /// <summary>
   /// Creates a preview of the message template provided in the request, normalized to a given locale.
   /// </summary>
   /// <param name="request"> The request that contains the email template and optionally a locale to render it in.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PreviewMessageTemplateResponse> RetrieveMessageTemplatePreview(PreviewMessageTemplateRequest request);

   /// <summary>
   /// Retrieves all the message templates.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessageTemplateResponse> RetrieveMessageTemplates();

   /// <summary>
   /// Retrieves the messenger with the given Id.
   /// </summary>
   /// <param name="messengerId"> The Id of the messenger.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessengerResponse> RetrieveMessenger(Guid? messengerId);

   /// <summary>
   /// Retrieves all the messengers.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessengerResponse> RetrieveMessengers();

   /// <summary>
   /// Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
   /// return the monthly active counts for that application.
   /// </summary>
   /// <param name="applicationId"> (Optional) The application id.</param>
   /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
   /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MonthlyActiveUserReportResponse> RetrieveMonthlyActiveReport(Guid? applicationId, long? start, long? end);

   /// <summary>
   /// Retrieves a custom OAuth scope.
   /// </summary>
   /// <param name="applicationId"> The Id of the application that the OAuth scope belongs to.</param>
   /// <param name="scopeId"> The Id of the OAuth scope to retrieve.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationOAuthScopeResponse> RetrieveOAuthScope(Guid? applicationId, Guid? scopeId);

   /// <summary>
   /// Retrieves the Oauth2 configuration for the application for the given Application Id.
   /// </summary>
   /// <param name="applicationId"> The Id of the Application to retrieve OAuth configuration.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<OAuthConfigurationResponse> RetrieveOauthConfiguration(Guid? applicationId);

   /// <summary>
   /// Returns the well known OpenID Configuration JSON document
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<OpenIdConfiguration> RetrieveOpenIdConfiguration();

   /// <summary>
   /// Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided 
   /// through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
   /// 
   /// This API does not require an API key.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PasswordValidationRulesResponse> RetrievePasswordValidationRules();

   /// <summary>
   /// Retrieves the password validation rules for a specific tenant.
   /// 
   /// This API does not require an API key.
   /// </summary>
   /// <param name="tenantId"> The Id of the tenant.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PasswordValidationRulesResponse> RetrievePasswordValidationRulesWithTenantId(Guid? tenantId);

   /// <summary>
   /// Retrieves all the children for the given parent email address.
   /// </summary>
   /// <param name="parentEmail"> The email of the parent.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PendingResponse> RetrievePendingChildren(string parentEmail);

   /// <summary>
   /// Retrieve a pending identity provider link. This is useful to validate a pending link and retrieve meta-data about the identity provider link.
   /// </summary>
   /// <param name="pendingLinkId"> The pending link Id.</param>
   /// <param name="userId"> The optional userId. When provided additional meta-data will be provided to identify how many links if any the user already has.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderPendingLinkResponse> RetrievePendingLink(string pendingLinkId, Guid? userId);

   /// <summary>
   /// Retrieves the FusionAuth Reactor metrics.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ReactorMetricsResponse> RetrieveReactorMetrics();

   /// <summary>
   /// Retrieves the FusionAuth Reactor status.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ReactorResponse> RetrieveReactorStatus();

   /// <summary>
   /// Retrieves the last number of login records.
   /// </summary>
   /// <param name="offset"> The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.</param>
   /// <param name="limit"> (Optional, defaults to 10) The number of records to retrieve.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RecentLoginResponse> RetrieveRecentLogins(int? offset, int? limit);

   /// <summary>
   /// Retrieves a single refresh token by unique Id. This is not the same thing as the string value of the refresh token. If you have that, you already have what you need.
   /// </summary>
   /// <param name="tokenId"> The Id of the token.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RefreshTokenResponse> RetrieveRefreshTokenById(Guid? tokenId);

   /// <summary>
   /// Retrieves the refresh tokens that belong to the user with the given Id.
   /// </summary>
   /// <param name="userId"> The Id of the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RefreshTokenResponse> RetrieveRefreshTokens(Guid? userId);

   /// <summary>
   /// Retrieves the user registration for the user with the given Id and the given application id.
   /// </summary>
   /// <param name="userId"> The Id of the user.</param>
   /// <param name="applicationId"> The Id of the application.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RegistrationResponse> RetrieveRegistration(Guid? userId, Guid? applicationId);

   /// <summary>
   /// Retrieves the registration report between the two instants. If you specify an application id, it will only return
   /// the registration counts for that application.
   /// </summary>
   /// <param name="applicationId"> (Optional) The application id.</param>
   /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
   /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RegistrationReportResponse> RetrieveRegistrationReport(Guid? applicationId, long? start, long? end);

   /// <summary>
   /// Retrieve the status of a re-index process. A status code of 200 indicates the re-index is in progress, a status code of  
   /// 404 indicates no re-index is in progress.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RetrieveReindexStatus();

   /// <summary>
   /// Retrieves the system configuration.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<SystemConfigurationResponse> RetrieveSystemConfiguration();

   /// <summary>
   /// Retrieves the tenant for the given Id.
   /// </summary>
   /// <param name="tenantId"> The Id of the tenant.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TenantResponse> RetrieveTenant(Guid? tenantId);

   /// <summary>
   /// Retrieves all the tenants.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TenantResponse> RetrieveTenants();

   /// <summary>
   /// Retrieves the theme for the given Id.
   /// </summary>
   /// <param name="themeId"> The Id of the theme.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ThemeResponse> RetrieveTheme(Guid? themeId);

   /// <summary>
   /// Retrieves all the themes.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ThemeResponse> RetrieveThemes();

   /// <summary>
   /// Retrieves the totals report. This contains all the total counts for each application and the global registration
   /// count.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TotalsReportResponse> RetrieveTotalReport();

   /// <summary>
   /// Retrieve two-factor recovery codes for a user.
   /// </summary>
   /// <param name="userId"> The Id of the user to retrieve Two Factor recovery codes.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TwoFactorRecoveryCodeResponse> RetrieveTwoFactorRecoveryCodes(Guid? userId);

   /// <summary>
   /// Retrieve a user's two-factor status.
   /// 
   /// This can be used to see if a user will need to complete a two-factor challenge to complete a login,
   /// and optionally identify the state of the two-factor trust across various applications.
   /// </summary>
   /// <param name="userId"> The user Id to retrieve the Two-Factor status.</param>
   /// <param name="applicationId"> The optional applicationId to verify.</param>
   /// <param name="twoFactorTrustId"> The optional two-factor trust Id to verify.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TwoFactorStatusResponse> RetrieveTwoFactorStatus(Guid? userId, Guid? applicationId, string twoFactorTrustId);

   /// <summary>
   /// Retrieves the user for the given Id.
   /// </summary>
   /// <param name="userId"> The Id of the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> RetrieveUser(Guid? userId);

   /// <summary>
   /// Retrieves the user action for the given Id. If you pass in null for the id, this will return all the user
   /// actions.
   /// </summary>
   /// <param name="userActionId"> (Optional) The Id of the user action.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionResponse> RetrieveUserAction(Guid? userActionId);

   /// <summary>
   /// Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all the user
   /// action reasons.
   /// </summary>
   /// <param name="userActionReasonId"> (Optional) The Id of the user action reason.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionReasonResponse> RetrieveUserActionReason(Guid? userActionReasonId);

   /// <summary>
   /// Retrieves all the user action reasons.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionReasonResponse> RetrieveUserActionReasons();

   /// <summary>
   /// Retrieves all the user actions.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionResponse> RetrieveUserActions();

   /// <summary>
   /// Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
   /// password workflow has been initiated and you may not know the user's email or username.
   /// </summary>
   /// <param name="changePasswordId"> The unique change password Id that was sent via email or returned by the Forgot Password API.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> RetrieveUserByChangePasswordId(string changePasswordId);

   /// <summary>
   /// Retrieves the user for the given email.
   /// </summary>
   /// <param name="email"> The email of the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> RetrieveUserByEmail(string email);

   /// <summary>
   /// Retrieves the user for the loginId. The loginId can be either the username or the email.
   /// </summary>
   /// <param name="loginId"> The email or username of the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> RetrieveUserByLoginId(string loginId);

   /// <summary>
   /// Retrieves the user for the given username.
   /// </summary>
   /// <param name="username"> The username of the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> RetrieveUserByUsername(string username);

   /// <summary>
   /// Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
   /// password workflow has been initiated and you may not know the user's email or username.
   /// </summary>
   /// <param name="verificationId"> The unique verification Id that has been set on the user object.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> RetrieveUserByVerificationId(string verificationId);

   /// <summary>
   /// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
   /// 
   /// This API is useful if you want to build your own login workflow to complete a device grant.
   /// </summary>
   /// <param name="client_id"> The client id.</param>
   /// <param name="client_secret"> The client id.</param>
   /// <param name="user_code"> The end-user verification code.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RetrieveUserCode(string client_id, string client_secret, string user_code);

   /// <summary>
   /// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
   /// 
   /// This API is useful if you want to build your own login workflow to complete a device grant.
   /// 
   /// This request will require an API key.
   /// </summary>
   /// <param name="user_code"> The end-user verification code.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RetrieveUserCodeUsingAPIKey(string user_code);

   /// <summary>
   /// Retrieves all the comments for the user with the given Id.
   /// </summary>
   /// <param name="userId"> The Id of the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserCommentResponse> RetrieveUserComments(Guid? userId);

   /// <summary>
   /// Retrieve a single User consent by Id.
   /// </summary>
   /// <param name="userConsentId"> The User consent Id</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserConsentResponse> RetrieveUserConsent(Guid? userConsentId);

   /// <summary>
   /// Retrieves all the consents for a User.
   /// </summary>
   /// <param name="userId"> The User's Id</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserConsentResponse> RetrieveUserConsents(Guid? userId);

   /// <summary>
   /// Call the UserInfo endpoint to retrieve User Claims from the access token issued by FusionAuth.
   /// </summary>
   /// <param name="encodedJWT"> The encoded JWT (access token).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserinfoResponse> RetrieveUserInfoFromAccessToken(string encodedJWT);

   /// <summary>
   /// Retrieve a single Identity Provider user (link).
   /// </summary>
   /// <param name="identityProviderId"> The unique Id of the identity provider.</param>
   /// <param name="identityProviderUserId"> The unique Id of the user in the 3rd party identity provider.</param>
   /// <param name="userId"> The unique Id of the FusionAuth user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderLinkResponse> RetrieveUserLink(Guid? identityProviderId, string identityProviderUserId, Guid? userId);

   /// <summary>
   /// Retrieve all Identity Provider users (links) for the user. Specify the optional identityProviderId to retrieve links for a particular IdP.
   /// </summary>
   /// <param name="identityProviderId"> (Optional) The unique Id of the identity provider. Specify this value to reduce the links returned to those for a particular IdP.</param>
   /// <param name="userId"> The unique Id of the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderLinkResponse> RetrieveUserLinksByUserId(Guid? identityProviderId, Guid? userId);

   /// <summary>
   /// Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
   /// login counts for that application.
   /// </summary>
   /// <param name="applicationId"> (Optional) The application id.</param>
   /// <param name="userId"> The userId id.</param>
   /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
   /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginReportResponse> RetrieveUserLoginReport(Guid? applicationId, Guid? userId, long? start, long? end);

   /// <summary>
   /// Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
   /// login counts for that application.
   /// </summary>
   /// <param name="applicationId"> (Optional) The application id.</param>
   /// <param name="loginId"> The userId id.</param>
   /// <param name="start"> The start instant as UTC milliseconds since Epoch.</param>
   /// <param name="end"> The end instant as UTC milliseconds since Epoch.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginReportResponse> RetrieveUserLoginReportByLoginId(Guid? applicationId, string loginId, long? start, long? end);

   /// <summary>
   /// Retrieves the last number of login records for a user.
   /// </summary>
   /// <param name="userId"> The Id of the user.</param>
   /// <param name="offset"> The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.</param>
   /// <param name="limit"> (Optional, defaults to 10) The number of records to retrieve.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RecentLoginResponse> RetrieveUserRecentLogins(Guid? userId, int? offset, int? limit);

   /// <summary>
   /// Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
   /// </summary>
   /// <param name="encodedJWT"> The encoded JWT (access token).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> RetrieveUserUsingJWT(string encodedJWT);

   /// <summary>
   /// Retrieves the FusionAuth version string.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<VersionResponse> RetrieveVersion();

   /// <summary>
   /// Retrieves the WebAuthn credential for the given Id.
   /// </summary>
   /// <param name="id"> The Id of the WebAuthn credential.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebAuthnCredentialResponse> RetrieveWebAuthnCredential(Guid? id);

   /// <summary>
   /// Retrieves all WebAuthn credentials for the given user.
   /// </summary>
   /// <param name="userId"> The user's ID.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebAuthnCredentialResponse> RetrieveWebAuthnCredentialsForUser(Guid? userId);

   /// <summary>
   /// Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
   /// </summary>
   /// <param name="webhookId"> (Optional) The Id of the webhook.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebhookResponse> RetrieveWebhook(Guid? webhookId);

   /// <summary>
   /// Retrieves all the webhooks.
   /// </summary>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebhookResponse> RetrieveWebhooks();

   /// <summary>
   /// Revokes refresh tokens.
   /// 
   /// Usage examples:
   ///   - Delete a single refresh token, pass in only the token.
   ///       revokeRefreshToken(token)
   /// 
   ///   - Delete all refresh tokens for a user, pass in only the userId.
   ///       revokeRefreshToken(null, userId)
   /// 
   ///   - Delete all refresh tokens for a user for a specific application, pass in both the userId and the applicationId.
   ///       revokeRefreshToken(null, userId, applicationId)
   /// 
   ///   - Delete all refresh tokens for an application
   ///       revokeRefreshToken(null, null, applicationId)
   /// 
   /// Note: <code>null</code> may be handled differently depending upon the programming language.
   /// 
   /// See also: (method names may vary by language... but you'll figure it out)
   /// 
   ///  - revokeRefreshTokenById
   ///  - revokeRefreshTokenByToken
   ///  - revokeRefreshTokensByUserId
   ///  - revokeRefreshTokensByApplicationId
   ///  - revokeRefreshTokensByUserIdForApplication
   /// </summary>
   /// <param name="token"> (Optional) The refresh token to delete.</param>
   /// <param name="userId"> (Optional) The user Id whose tokens to delete.</param>
   /// <param name="applicationId"> (Optional) The application Id of the tokens to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RevokeRefreshToken(string token, Guid? userId, Guid? applicationId);

   /// <summary>
   /// Revokes a single refresh token by the unique Id. The unique Id is not sensitive as it cannot be used to obtain another JWT.
   /// </summary>
   /// <param name="tokenId"> The unique Id of the token to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RevokeRefreshTokenById(Guid? tokenId);

   /// <summary>
   /// Revokes a single refresh token by using the actual refresh token value. This refresh token value is sensitive, so  be careful with this API request.
   /// </summary>
   /// <param name="token"> The refresh token to delete.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RevokeRefreshTokenByToken(string token);

   /// <summary>
   /// Revoke all refresh tokens that belong to an application by applicationId.
   /// </summary>
   /// <param name="applicationId"> The unique Id of the application that you want to delete all refresh tokens for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RevokeRefreshTokensByApplicationId(Guid? applicationId);

   /// <summary>
   /// Revoke all refresh tokens that belong to a user by user Id.
   /// </summary>
   /// <param name="userId"> The unique Id of the user that you want to delete all refresh tokens for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RevokeRefreshTokensByUserId(Guid? userId);

   /// <summary>
   /// Revoke all refresh tokens that belong to a user by user Id for a specific application by applicationId.
   /// </summary>
   /// <param name="userId"> The unique Id of the user that you want to delete all refresh tokens for.</param>
   /// <param name="applicationId"> The unique Id of the application that you want to delete refresh tokens for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RevokeRefreshTokensByUserIdForApplication(Guid? userId, Guid? applicationId);

   /// <summary>
   /// Revokes refresh tokens using the information in the JSON body. The handling for this method is the same as the revokeRefreshToken method
   /// and is based on the information you provide in the RefreshDeleteRequest object. See that method for additional information.
   /// </summary>
   /// <param name="request"> The request information used to revoke the refresh tokens.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RevokeRefreshTokensWithRequest(RefreshTokenRevokeRequest request);

   /// <summary>
   /// Revokes a single User consent by Id.
   /// </summary>
   /// <param name="userConsentId"> The User Consent Id</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> RevokeUserConsent(Guid? userConsentId);

   /// <summary>
   /// Searches applications with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationSearchResponse> SearchApplications(ApplicationSearchRequest request);

   /// <summary>
   /// Searches the audit logs with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<AuditLogSearchResponse> SearchAuditLogs(AuditLogSearchRequest request);

   /// <summary>
   /// Searches consents with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConsentSearchResponse> SearchConsents(ConsentSearchRequest request);

   /// <summary>
   /// Searches email templates with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EmailTemplateSearchResponse> SearchEmailTemplates(EmailTemplateSearchRequest request);

   /// <summary>
   /// Searches entities with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntitySearchResponse> SearchEntities(EntitySearchRequest request);

   /// <summary>
   /// Retrieves the entities for the given ids. If any Id is invalid, it is ignored.
   /// </summary>
   /// <param name="ids"> The entity ids to search for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntitySearchResponse> SearchEntitiesByIds(List<string> ids);

   /// <summary>
   /// Searches Entity Grants with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityGrantSearchResponse> SearchEntityGrants(EntityGrantSearchRequest request);

   /// <summary>
   /// Searches the entity types with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityTypeSearchResponse> SearchEntityTypes(EntityTypeSearchRequest request);

   /// <summary>
   /// Searches the event logs with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EventLogSearchResponse> SearchEventLogs(EventLogSearchRequest request);

   /// <summary>
   /// Searches group members with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<GroupMemberSearchResponse> SearchGroupMembers(GroupMemberSearchRequest request);

   /// <summary>
   /// Searches groups with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<GroupSearchResponse> SearchGroups(GroupSearchRequest request);

   /// <summary>
   /// Searches the IP Access Control Lists with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IPAccessControlListSearchResponse> SearchIPAccessControlLists(IPAccessControlListSearchRequest request);

   /// <summary>
   /// Searches identity providers with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderSearchResponse> SearchIdentityProviders(IdentityProviderSearchRequest request);

   /// <summary>
   /// Searches keys with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<KeySearchResponse> SearchKeys(KeySearchRequest request);

   /// <summary>
   /// Searches lambdas with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LambdaSearchResponse> SearchLambdas(LambdaSearchRequest request);

   /// <summary>
   /// Searches the login records with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginRecordSearchResponse> SearchLoginRecords(LoginRecordSearchRequest request);

   /// <summary>
   /// Searches tenants with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TenantSearchResponse> SearchTenants(TenantSearchRequest request);

   /// <summary>
   /// Searches themes with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ThemeSearchResponse> SearchThemes(ThemeSearchRequest request);

   /// <summary>
   /// Searches user comments with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserCommentSearchResponse> SearchUserComments(UserCommentSearchRequest request);

   /// <summary>
   /// Retrieves the users for the given ids. If any Id is invalid, it is ignored.
   /// </summary>
   /// <param name="ids"> The user ids to search for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   [Obsolete("This method has been renamed to SearchUsersByIdsAsync, use that method instead.")]
   ClientResponse<SearchResponse> SearchUsers(List<string> ids);

   /// <summary>
   /// Retrieves the users for the given ids. If any Id is invalid, it is ignored.
   /// </summary>
   /// <param name="ids"> The user ids to search for.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<SearchResponse> SearchUsersByIds(List<string> ids);

   /// <summary>
   /// Retrieves the users for the given search criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
    /// and sortFields.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<SearchResponse> SearchUsersByQuery(SearchRequest request);

   /// <summary>
   /// Retrieves the users for the given search criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
    /// and sortFields.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   [Obsolete("This method has been renamed to SearchUsersByQueryAsync, use that method instead.")]
   ClientResponse<SearchResponse> SearchUsersByQueryString(SearchRequest request);

   /// <summary>
   /// Searches webhooks with the specified criteria and pagination.
   /// </summary>
   /// <param name="request"> The search criteria and pagination information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebhookSearchResponse> SearchWebhooks(WebhookSearchRequest request);

   /// <summary>
   /// Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
   /// pairs in the email template.
   /// </summary>
   /// <param name="emailTemplateId"> The Id for the template.</param>
   /// <param name="request"> The send email request that contains all the information used to send the email.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<SendResponse> SendEmail(Guid? emailTemplateId, SendRequest request);

   /// <summary>
   /// Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
   /// </summary>
   /// <param name="request"> The request object that contains the parent email.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> SendFamilyRequestEmail(FamilyEmailRequest request);

   /// <summary>
   /// Send a passwordless authentication code in an email to complete login.
   /// </summary>
   /// <param name="request"> The passwordless send request that contains all the information used to send an email containing a code.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> SendPasswordlessCode(PasswordlessSendRequest request);

   /// <summary>
   /// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
   /// </summary>
   /// <param name="request"> The request object that contains all the information used to send the code.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   [Obsolete("This method has been renamed to SendTwoFactorCodeForEnableDisableAsync, use that method instead.")]
   ClientResponse<RESTVoid> SendTwoFactorCode(TwoFactorSendRequest request);

   /// <summary>
   /// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
   /// </summary>
   /// <param name="request"> The request object that contains all the information used to send the code.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> SendTwoFactorCodeForEnableDisable(TwoFactorSendRequest request);

   /// <summary>
   /// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
   /// </summary>
   /// <param name="twoFactorId"> The Id returned by the Login API necessary to complete Two Factor authentication.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   [Obsolete("This method has been renamed to SendTwoFactorCodeForLoginUsingMethodAsync, use that method instead.")]
   ClientResponse<RESTVoid> SendTwoFactorCodeForLogin(string twoFactorId);

   /// <summary>
   /// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
   /// </summary>
   /// <param name="twoFactorId"> The Id returned by the Login API necessary to complete Two Factor authentication.</param>
   /// <param name="request"> The Two Factor send request that contains all the information used to send the Two Factor code to the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> SendTwoFactorCodeForLoginUsingMethod(string twoFactorId, TwoFactorSendRequest request);

   /// <summary>
   /// Begins a login request for a 3rd party login that requires user interaction such as HYPR.
   /// </summary>
   /// <param name="request"> The third-party login request that contains information from the third-party login
    /// providers that FusionAuth uses to reconcile the user's account.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderStartLoginResponse> StartIdentityProviderLogin(IdentityProviderStartLoginRequest request);

   /// <summary>
   /// Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
   /// Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
   /// </summary>
   /// <param name="request"> The passwordless start request that contains all the information used to begin the passwordless login request.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<PasswordlessStartResponse> StartPasswordlessLogin(PasswordlessStartRequest request);

   /// <summary>
   /// Start a Two-Factor login request by generating a two-factor identifier. This code can then be sent to the Two Factor Send 
   /// API (/api/two-factor/send)in order to send a one-time use code to a user. You can also use one-time use code returned 
   /// to send the code out-of-band. The Two-Factor login is completed by making a request to the Two-Factor Login 
   /// API (/api/two-factor/login). with the two-factor identifier and the one-time use code.
   /// 
   /// This API is intended to allow you to begin a Two-Factor login outside a normal login that originated from the Login API (/api/login).
   /// </summary>
   /// <param name="request"> The Two-Factor start request that contains all the information used to begin the Two-Factor login request.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TwoFactorStartResponse> StartTwoFactorLogin(TwoFactorStartRequest request);

   /// <summary>
   /// Start a WebAuthn authentication ceremony by generating a new challenge for the user
   /// </summary>
   /// <param name="request"> An object containing data necessary for starting the authentication ceremony</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebAuthnStartResponse> StartWebAuthnLogin(WebAuthnStartRequest request);

   /// <summary>
   /// Start a WebAuthn registration ceremony by generating a new challenge for the user
   /// </summary>
   /// <param name="request"> An object containing data necessary for starting the registration ceremony</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebAuthnRegisterStartResponse> StartWebAuthnRegistration(WebAuthnRegisterStartRequest request);

   /// <summary>
   /// Complete login using a 2FA challenge
   /// </summary>
   /// <param name="request"> The login request that contains the user credentials used to log them in.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LoginResponse> TwoFactorLogin(TwoFactorLoginRequest request);

   /// <summary>
   /// Updates an API key by given id
   /// </summary>
   /// <param name="apiKeyId"> The Id of the API key to update.</param>
   /// <param name="request"> The request object that contains all the information used to create the API Key.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<APIKeyResponse> UpdateAPIKey(Guid? apiKeyId, APIKeyRequest request);

   /// <summary>
   /// Updates the application with the given Id.
   /// </summary>
   /// <param name="applicationId"> The Id of the application to update.</param>
   /// <param name="request"> The request that contains all the new application information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> UpdateApplication(Guid? applicationId, ApplicationRequest request);

   /// <summary>
   /// Updates the application role with the given Id for the application.
   /// </summary>
   /// <param name="applicationId"> The Id of the application that the role belongs to.</param>
   /// <param name="roleId"> The Id of the role to update.</param>
   /// <param name="request"> The request that contains all the new role information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationResponse> UpdateApplicationRole(Guid? applicationId, Guid? roleId, ApplicationRequest request);

   /// <summary>
   /// Updates the connector with the given Id.
   /// </summary>
   /// <param name="connectorId"> The Id of the connector to update.</param>
   /// <param name="request"> The request object that contains all the new connector information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConnectorResponse> UpdateConnector(Guid? connectorId, ConnectorRequest request);

   /// <summary>
   /// Updates the consent with the given Id.
   /// </summary>
   /// <param name="consentId"> The Id of the consent to update.</param>
   /// <param name="request"> The request that contains all the new consent information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ConsentResponse> UpdateConsent(Guid? consentId, ConsentRequest request);

   /// <summary>
   /// Updates the email template with the given Id.
   /// </summary>
   /// <param name="emailTemplateId"> The Id of the email template to update.</param>
   /// <param name="request"> The request that contains all the new email template information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EmailTemplateResponse> UpdateEmailTemplate(Guid? emailTemplateId, EmailTemplateRequest request);

   /// <summary>
   /// Updates the Entity with the given Id.
   /// </summary>
   /// <param name="entityId"> The Id of the Entity to update.</param>
   /// <param name="request"> The request that contains all the new Entity information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityResponse> UpdateEntity(Guid? entityId, EntityRequest request);

   /// <summary>
   /// Updates the Entity Type with the given Id.
   /// </summary>
   /// <param name="entityTypeId"> The Id of the Entity Type to update.</param>
   /// <param name="request"> The request that contains all the new Entity Type information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityTypeResponse> UpdateEntityType(Guid? entityTypeId, EntityTypeRequest request);

   /// <summary>
   /// Updates the permission with the given Id for the entity type.
   /// </summary>
   /// <param name="entityTypeId"> The Id of the entityType that the permission belongs to.</param>
   /// <param name="permissionId"> The Id of the permission to update.</param>
   /// <param name="request"> The request that contains all the new permission information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<EntityTypeResponse> UpdateEntityTypePermission(Guid? entityTypeId, Guid? permissionId, EntityTypeRequest request);

   /// <summary>
   /// Updates the form with the given Id.
   /// </summary>
   /// <param name="formId"> The Id of the form to update.</param>
   /// <param name="request"> The request object that contains all the new form information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FormResponse> UpdateForm(Guid? formId, FormRequest request);

   /// <summary>
   /// Updates the form field with the given Id.
   /// </summary>
   /// <param name="fieldId"> The Id of the form field to update.</param>
   /// <param name="request"> The request object that contains all the new form field information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<FormFieldResponse> UpdateFormField(Guid? fieldId, FormFieldRequest request);

   /// <summary>
   /// Updates the group with the given Id.
   /// </summary>
   /// <param name="groupId"> The Id of the group to update.</param>
   /// <param name="request"> The request that contains all the new group information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<GroupResponse> UpdateGroup(Guid? groupId, GroupRequest request);

   /// <summary>
   /// Creates a member in a group.
   /// </summary>
   /// <param name="request"> The request object that contains all the information used to create the group member(s).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MemberResponse> UpdateGroupMembers(MemberRequest request);

   /// <summary>
   /// Updates the IP Access Control List with the given Id.
   /// </summary>
   /// <param name="accessControlListId"> The Id of the IP Access Control List to update.</param>
   /// <param name="request"> The request that contains all the new IP Access Control List information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IPAccessControlListResponse> UpdateIPAccessControlList(Guid? accessControlListId, IPAccessControlListRequest request);

   /// <summary>
   /// Updates the identity provider with the given Id.
   /// </summary>
   /// <param name="identityProviderId"> The Id of the identity provider to update.</param>
   /// <param name="request"> The request object that contains the updated identity provider.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IdentityProviderResponse> UpdateIdentityProvider(Guid? identityProviderId, IdentityProviderRequest request);

   /// <summary>
   /// Updates the available integrations.
   /// </summary>
   /// <param name="request"> The request that contains all the new integration information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<IntegrationResponse> UpdateIntegrations(IntegrationRequest request);

   /// <summary>
   /// Updates the key with the given Id.
   /// </summary>
   /// <param name="keyId"> The Id of the key to update.</param>
   /// <param name="request"> The request that contains all the new key information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<KeyResponse> UpdateKey(Guid? keyId, KeyRequest request);

   /// <summary>
   /// Updates the lambda with the given Id.
   /// </summary>
   /// <param name="lambdaId"> The Id of the lambda to update.</param>
   /// <param name="request"> The request that contains all the new lambda information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<LambdaResponse> UpdateLambda(Guid? lambdaId, LambdaRequest request);

   /// <summary>
   /// Updates the message template with the given Id.
   /// </summary>
   /// <param name="messageTemplateId"> The Id of the message template to update.</param>
   /// <param name="request"> The request that contains all the new message template information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessageTemplateResponse> UpdateMessageTemplate(Guid? messageTemplateId, MessageTemplateRequest request);

   /// <summary>
   /// Updates the messenger with the given Id.
   /// </summary>
   /// <param name="messengerId"> The Id of the messenger to update.</param>
   /// <param name="request"> The request object that contains all the new messenger information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<MessengerResponse> UpdateMessenger(Guid? messengerId, MessengerRequest request);

   /// <summary>
   /// Updates the OAuth scope with the given Id for the application.
   /// </summary>
   /// <param name="applicationId"> The Id of the application that the OAuth scope belongs to.</param>
   /// <param name="scopeId"> The Id of the OAuth scope to update.</param>
   /// <param name="request"> The request that contains all the new OAuth scope information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ApplicationOAuthScopeResponse> UpdateOAuthScope(Guid? applicationId, Guid? scopeId, ApplicationOAuthScopeRequest request);

   /// <summary>
   /// Updates the registration for the user with the given Id and the application defined in the request.
   /// </summary>
   /// <param name="userId"> The Id of the user whose registration is going to be updated.</param>
   /// <param name="request"> The request that contains all the new registration information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RegistrationResponse> UpdateRegistration(Guid? userId, RegistrationRequest request);

   /// <summary>
   /// Updates the system configuration.
   /// </summary>
   /// <param name="request"> The request that contains all the new system configuration information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<SystemConfigurationResponse> UpdateSystemConfiguration(SystemConfigurationRequest request);

   /// <summary>
   /// Updates the tenant with the given Id.
   /// </summary>
   /// <param name="tenantId"> The Id of the tenant to update.</param>
   /// <param name="request"> The request that contains all the new tenant information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<TenantResponse> UpdateTenant(Guid? tenantId, TenantRequest request);

   /// <summary>
   /// Updates the theme with the given Id.
   /// </summary>
   /// <param name="themeId"> The Id of the theme to update.</param>
   /// <param name="request"> The request that contains all the new theme information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ThemeResponse> UpdateTheme(Guid? themeId, ThemeRequest request);

   /// <summary>
   /// Updates the user with the given Id.
   /// </summary>
   /// <param name="userId"> The Id of the user to update.</param>
   /// <param name="request"> The request that contains all the new user information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserResponse> UpdateUser(Guid? userId, UserRequest request);

   /// <summary>
   /// Updates the user action with the given Id.
   /// </summary>
   /// <param name="userActionId"> The Id of the user action to update.</param>
   /// <param name="request"> The request that contains all the new user action information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionResponse> UpdateUserAction(Guid? userActionId, UserActionRequest request);

   /// <summary>
   /// Updates the user action reason with the given Id.
   /// </summary>
   /// <param name="userActionReasonId"> The Id of the user action reason to update.</param>
   /// <param name="request"> The request that contains all the new user action reason information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserActionReasonResponse> UpdateUserActionReason(Guid? userActionReasonId, UserActionReasonRequest request);

   /// <summary>
   /// Updates a single User consent by Id.
   /// </summary>
   /// <param name="userConsentId"> The User Consent Id</param>
   /// <param name="request"> The request that contains the user consent information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<UserConsentResponse> UpdateUserConsent(Guid? userConsentId, UserConsentRequest request);

   /// <summary>
   /// Updates the webhook with the given Id.
   /// </summary>
   /// <param name="webhookId"> The Id of the webhook to update.</param>
   /// <param name="request"> The request that contains all the new webhook information.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<WebhookResponse> UpdateWebhook(Guid? webhookId, WebhookRequest request);

   /// <summary>
   /// Creates or updates an Entity Grant. This is when a User/Entity is granted permissions to an Entity.
   /// </summary>
   /// <param name="entityId"> The Id of the Entity that the User/Entity is being granted access to.</param>
   /// <param name="request"> The request object that contains all the information used to create the Entity Grant.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> UpsertEntityGrant(Guid? entityId, EntityGrantRequest request);

   /// <summary>
   /// Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
   /// If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
   /// </summary>
   /// <param name="user_code"> The end-user verification code.</param>
   /// <param name="client_id"> The client id.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> ValidateDevice(string user_code, string client_id);

   /// <summary>
   /// Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
   /// signed and not expired.
   /// <p>
   /// This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
   /// </summary>
   /// <param name="encodedJWT"> The encoded JWT (access token).</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<ValidateResponse> ValidateJWT(string encodedJWT);

   /// <summary>
   /// It's a JWT vending machine!
   /// 
   /// Issue a new access token (JWT) with the provided claims in the request. This JWT is not scoped to a tenant or user, it is a free form 
   /// token that will contain what claims you provide.
   /// <p>
   /// The iat, exp and jti claims will be added by FusionAuth, all other claims must be provided by the caller.
   /// 
   /// If a TTL is not provided in the request, the TTL will be retrieved from the default Tenant or the Tenant specified on the request either 
   /// by way of the X-FusionAuth-TenantId request header, or a tenant scoped API key.
   /// </summary>
   /// <param name="request"> The request that contains all the claims for this JWT.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<JWTVendResponse> VendJWT(JWTVendRequest request);

   /// <summary>
   /// Confirms a email verification. The Id given is usually from an email sent to the user.
   /// </summary>
   /// <param name="verificationId"> The email verification Id sent to the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   [Obsolete("This method has been renamed to VerifyEmailAddressAsync and changed to take a JSON request body, use that method instead.")]
   ClientResponse<RESTVoid> VerifyEmail(string verificationId);

   /// <summary>
   /// Confirms a user's email address. 
   /// 
   /// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When 
   /// the tenant is configured to gate a user until their email address is verified, this procedures requires two values instead of one. 
   /// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The 
   /// two values together are able to confirm a user's email address and mark the user's email address as verified.
   /// </summary>
   /// <param name="request"> The request that contains the verificationId and optional one-time use code paired with the verificationId.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> VerifyEmailAddress(VerifyEmailRequest request);

   /// <summary>
   /// Administratively verify a user's email address. Use this method to bypass email verification for the user.
   /// 
   /// The request body will contain the userId to be verified. An API key is required when sending the userId in the request body.
   /// </summary>
   /// <param name="request"> The request that contains the userId to verify.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> VerifyEmailAddressByUserId(VerifyEmailRequest request);

   /// <summary>
   /// Confirms an application registration. The Id given is usually from an email sent to the user.
   /// </summary>
   /// <param name="verificationId"> The registration verification Id sent to the user.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   [Obsolete("This method has been renamed to VerifyUserRegistrationAsync and changed to take a JSON request body, use that method instead.")]
   ClientResponse<RESTVoid> VerifyRegistration(string verificationId);

   /// <summary>
   /// Confirms a user's registration. 
   /// 
   /// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When 
   /// the application is configured to gate a user until their registration is verified, this procedures requires two values instead of one. 
   /// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The 
   /// two values together are able to confirm a user's registration and mark the user's registration as verified.
   /// </summary>
   /// <param name="request"> The request that contains the verificationId and optional one-time use code paired with the verificationId.</param>
   /// <returns>
   /// When successful, the response will contain the log of the action. If there was a validation error or any
   /// other type of error, this will return the Errors object in the response. Additionally, if FusionAuth could not be
   /// contacted because it is down or experiencing a failure, the response will contain an Exception, which could be an
   /// IOException.
   /// </returns>
   ClientResponse<RESTVoid> VerifyUserRegistration(VerifyRegistrationRequest request);
 }
}
