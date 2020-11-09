/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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
using io.fusionauth.domain.oauth2;

namespace io.fusionauth {
  public class FusionAuthSyncClient : IFusionAuthSyncClient {
    public readonly FusionAuthClient client;

    public FusionAuthSyncClient(string apiKey, string host, string tenantId = null) {
      client = new FusionAuthClient(apiKey, host, tenantId);
    }

    /// <inheritdoc/>
    public ClientResponse<ActionResponse> ActionUser(ActionRequest request) {
      return client.ActionUserAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FamilyResponse> AddUserToFamily(Guid? familyId, FamilyRequest request) {
      return client.AddUserToFamilyAsync(familyId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ActionResponse> CancelAction(Guid? actionId, ActionRequest request) {
      return client.CancelActionAsync(actionId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ChangePasswordResponse> ChangePassword(string changePasswordId, ChangePasswordRequest request) {
      return client.ChangePasswordAsync(changePasswordId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> ChangePasswordByIdentity(ChangePasswordRequest request) {
      return client.ChangePasswordByIdentityAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> CommentOnUser(UserCommentRequest request) {
      return client.CommentOnUserAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> CreateApplication(Guid? applicationId, ApplicationRequest request) {
      return client.CreateApplicationAsync(applicationId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> CreateApplicationRole(Guid? applicationId, Guid? roleId, ApplicationRequest request) {
      return client.CreateApplicationRoleAsync(applicationId, roleId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<AuditLogResponse> CreateAuditLog(AuditLogRequest request) {
      return client.CreateAuditLogAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConnectorResponse> CreateConnector(Guid? connectorId, ConnectorRequest request) {
      return client.CreateConnectorAsync(connectorId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConsentResponse> CreateConsent(Guid? consentId, ConsentRequest request) {
      return client.CreateConsentAsync(consentId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<EmailTemplateResponse> CreateEmailTemplate(Guid? emailTemplateId, EmailTemplateRequest request) {
      return client.CreateEmailTemplateAsync(emailTemplateId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FamilyResponse> CreateFamily(Guid? familyId, FamilyRequest request) {
      return client.CreateFamilyAsync(familyId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FormResponse> CreateForm(Guid? formId, FormRequest request) {
      return client.CreateFormAsync(formId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FormFieldResponse> CreateFormField(Guid? fieldId, FormFieldRequest request) {
      return client.CreateFormFieldAsync(fieldId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<GroupResponse> CreateGroup(Guid? groupId, GroupRequest request) {
      return client.CreateGroupAsync(groupId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<MemberResponse> CreateGroupMembers(MemberRequest request) {
      return client.CreateGroupMembersAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IdentityProviderResponse> CreateIdentityProvider(Guid? identityProviderId, IdentityProviderRequest request) {
      return client.CreateIdentityProviderAsync(identityProviderId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LambdaResponse> CreateLambda(Guid? lambdaId, LambdaRequest request) {
      return client.CreateLambdaAsync(lambdaId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<TenantResponse> CreateTenant(Guid? tenantId, TenantRequest request) {
      return client.CreateTenantAsync(tenantId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ThemeResponse> CreateTheme(Guid? themeId, ThemeRequest request) {
      return client.CreateThemeAsync(themeId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> CreateUser(Guid? userId, UserRequest request) {
      return client.CreateUserAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionResponse> CreateUserAction(Guid? userActionId, UserActionRequest request) {
      return client.CreateUserActionAsync(userActionId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionReasonResponse> CreateUserActionReason(Guid? userActionReasonId, UserActionReasonRequest request) {
      return client.CreateUserActionReasonAsync(userActionReasonId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserConsentResponse> CreateUserConsent(Guid? userConsentId, UserConsentRequest request) {
      return client.CreateUserConsentAsync(userConsentId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<WebhookResponse> CreateWebhook(Guid? webhookId, WebhookRequest request) {
      return client.CreateWebhookAsync(webhookId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeactivateApplication(Guid? applicationId) {
      return client.DeactivateApplicationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeactivateUser(Guid? userId) {
      return client.DeactivateUserAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeactivateUserAction(Guid? userActionId) {
      return client.DeactivateUserActionAsync(userActionId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to DeactivateUsersByIds, use that method instead.")]
    public ClientResponse<UserDeleteResponse> DeactivateUsers(List<string> userIds) {
      return client.DeactivateUsersAsync(userIds).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserDeleteResponse> DeactivateUsersByIds(List<string> userIds) {
      return client.DeactivateUsersByIdsAsync(userIds).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteApplication(Guid? applicationId) {
      return client.DeleteApplicationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteApplicationRole(Guid? applicationId, Guid? roleId) {
      return client.DeleteApplicationRoleAsync(applicationId, roleId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteConnector(Guid? connectorId) {
      return client.DeleteConnectorAsync(connectorId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteConsent(Guid? consentId) {
      return client.DeleteConsentAsync(consentId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteEmailTemplate(Guid? emailTemplateId) {
      return client.DeleteEmailTemplateAsync(emailTemplateId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteForm(Guid? formId) {
      return client.DeleteFormAsync(formId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteFormField(Guid? fieldId) {
      return client.DeleteFormFieldAsync(fieldId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteGroup(Guid? groupId) {
      return client.DeleteGroupAsync(groupId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteGroupMembers(MemberDeleteRequest request) {
      return client.DeleteGroupMembersAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteIdentityProvider(Guid? identityProviderId) {
      return client.DeleteIdentityProviderAsync(identityProviderId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteKey(Guid? keyId) {
      return client.DeleteKeyAsync(keyId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteLambda(Guid? lambdaId) {
      return client.DeleteLambdaAsync(lambdaId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteRegistration(Guid? userId, Guid? applicationId) {
      return client.DeleteRegistrationAsync(userId, applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteTenant(Guid? tenantId) {
      return client.DeleteTenantAsync(tenantId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteTheme(Guid? themeId) {
      return client.DeleteThemeAsync(themeId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteUser(Guid? userId) {
      return client.DeleteUserAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteUserAction(Guid? userActionId) {
      return client.DeleteUserActionAsync(userActionId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteUserActionReason(Guid? userActionReasonId) {
      return client.DeleteUserActionReasonAsync(userActionReasonId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to DeleteUsersByQuery, use that method instead.")]
    public ClientResponse<UserDeleteResponse> DeleteUsers(UserDeleteRequest request) {
      return client.DeleteUsersAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserDeleteResponse> DeleteUsersByQuery(UserDeleteRequest request) {
      return client.DeleteUsersByQueryAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DeleteWebhook(Guid? webhookId) {
      return client.DeleteWebhookAsync(webhookId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> DisableTwoFactor(Guid? userId, string code) {
      return client.DisableTwoFactorAsync(userId, code).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> EnableTwoFactor(Guid? userId, TwoFactorRequest request) {
      return client.EnableTwoFactorAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<AccessToken> ExchangeOAuthCodeForAccessToken(string code, string client_id, string client_secret, string redirect_uri) {
      return client.ExchangeOAuthCodeForAccessTokenAsync(code, client_id, client_secret, redirect_uri).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<AccessToken> ExchangeOAuthCodeForAccessTokenUsingPKCE(string code, string client_id, string client_secret, string redirect_uri, string code_verifier) {
      return client.ExchangeOAuthCodeForAccessTokenUsingPKCEAsync(code, client_id, client_secret, redirect_uri, code_verifier).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<AccessToken> ExchangeRefreshTokenForAccessToken(string refresh_token, string client_id, string client_secret, string scope, string user_code) {
      return client.ExchangeRefreshTokenForAccessTokenAsync(refresh_token, client_id, client_secret, scope, user_code).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RefreshResponse> ExchangeRefreshTokenForJWT(RefreshRequest request) {
      return client.ExchangeRefreshTokenForJWTAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<AccessToken> ExchangeUserCredentialsForAccessToken(string username, string password, string client_id, string client_secret, string scope, string user_code) {
      return client.ExchangeUserCredentialsForAccessTokenAsync(username, password, client_id, client_secret, scope, user_code).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ForgotPasswordResponse> ForgotPassword(ForgotPasswordRequest request) {
      return client.ForgotPasswordAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<VerifyEmailResponse> GenerateEmailVerificationId(string email) {
      return client.GenerateEmailVerificationIdAsync(email).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<KeyResponse> GenerateKey(Guid? keyId, KeyRequest request) {
      return client.GenerateKeyAsync(keyId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<VerifyRegistrationResponse> GenerateRegistrationVerificationId(string email, Guid? applicationId) {
      return client.GenerateRegistrationVerificationIdAsync(email, applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<SecretResponse> GenerateTwoFactorSecret() {
      return client.GenerateTwoFactorSecretAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<SecretResponse> GenerateTwoFactorSecretUsingJWT(string encodedJWT) {
      return client.GenerateTwoFactorSecretUsingJWTAsync(encodedJWT).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginResponse> IdentityProviderLogin(IdentityProviderLoginRequest request) {
      return client.IdentityProviderLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<KeyResponse> ImportKey(Guid? keyId, KeyRequest request) {
      return client.ImportKeyAsync(keyId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> ImportRefreshTokens(RefreshTokenImportRequest request) {
      return client.ImportRefreshTokensAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> ImportUsers(ImportRequest request) {
      return client.ImportUsersAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IntrospectResponse> IntrospectAccessToken(string client_id, string token) {
      return client.IntrospectAccessTokenAsync(client_id, token).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IssueResponse> IssueJWT(Guid? applicationId, string encodedJWT, string refreshToken) {
      return client.IssueJWTAsync(applicationId, encodedJWT, refreshToken).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginResponse> Login(LoginRequest request) {
      return client.LoginAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> LoginPing(Guid? userId, Guid? applicationId, string callerIPAddress) {
      return client.LoginPingAsync(userId, applicationId, callerIPAddress).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> Logout(bool? global, string refreshToken) {
      return client.LogoutAsync(global, refreshToken).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LookupResponse> LookupIdentityProvider(string domain) {
      return client.LookupIdentityProviderAsync(domain).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ActionResponse> ModifyAction(Guid? actionId, ActionRequest request) {
      return client.ModifyActionAsync(actionId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginResponse> PasswordlessLogin(PasswordlessLoginRequest request) {
      return client.PasswordlessLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> PatchApplication(Guid? applicationId, Dictionary<string, object> request) {
      return client.PatchApplicationAsync(applicationId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> PatchApplicationRole(Guid? applicationId, Guid? roleId, Dictionary<string, object> request) {
      return client.PatchApplicationRoleAsync(applicationId, roleId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConnectorResponse> PatchConnector(Guid? connectorId, Dictionary<string, object> request) {
      return client.PatchConnectorAsync(connectorId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConsentResponse> PatchConsent(Guid? consentId, Dictionary<string, object> request) {
      return client.PatchConsentAsync(consentId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<EmailTemplateResponse> PatchEmailTemplate(Guid? emailTemplateId, Dictionary<string, object> request) {
      return client.PatchEmailTemplateAsync(emailTemplateId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<GroupResponse> PatchGroup(Guid? groupId, Dictionary<string, object> request) {
      return client.PatchGroupAsync(groupId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IdentityProviderResponse> PatchIdentityProvider(Guid? identityProviderId, Dictionary<string, object> request) {
      return client.PatchIdentityProviderAsync(identityProviderId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IntegrationResponse> PatchIntegrations(Dictionary<string, object> request) {
      return client.PatchIntegrationsAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LambdaResponse> PatchLambda(Guid? lambdaId, Dictionary<string, object> request) {
      return client.PatchLambdaAsync(lambdaId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RegistrationResponse> PatchRegistration(Guid? userId, Dictionary<string, object> request) {
      return client.PatchRegistrationAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<SystemConfigurationResponse> PatchSystemConfiguration(Dictionary<string, object> request) {
      return client.PatchSystemConfigurationAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<TenantResponse> PatchTenant(Guid? tenantId, Dictionary<string, object> request) {
      return client.PatchTenantAsync(tenantId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ThemeResponse> PatchTheme(Guid? themeId, Dictionary<string, object> request) {
      return client.PatchThemeAsync(themeId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> PatchUser(Guid? userId, Dictionary<string, object> request) {
      return client.PatchUserAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionResponse> PatchUserAction(Guid? userActionId, Dictionary<string, object> request) {
      return client.PatchUserActionAsync(userActionId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionReasonResponse> PatchUserActionReason(Guid? userActionReasonId, Dictionary<string, object> request) {
      return client.PatchUserActionReasonAsync(userActionReasonId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserConsentResponse> PatchUserConsent(Guid? userConsentId, Dictionary<string, object> request) {
      return client.PatchUserConsentAsync(userConsentId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> ReactivateApplication(Guid? applicationId) {
      return client.ReactivateApplicationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> ReactivateUser(Guid? userId) {
      return client.ReactivateUserAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionResponse> ReactivateUserAction(Guid? userActionId) {
      return client.ReactivateUserActionAsync(userActionId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginResponse> ReconcileJWT(IdentityProviderLoginRequest request) {
      return client.ReconcileJWTAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> RefreshUserSearchIndex() {
      return client.RefreshUserSearchIndexAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RegistrationResponse> Register(Guid? userId, RegistrationRequest request) {
      return client.RegisterAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> RemoveUserFromFamily(Guid? familyId, Guid? userId) {
      return client.RemoveUserFromFamilyAsync(familyId, userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<VerifyEmailResponse> ResendEmailVerification(string email) {
      return client.ResendEmailVerificationAsync(email).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<VerifyEmailResponse> ResendEmailVerificationWithApplicationTemplate(Guid? applicationId, string email) {
      return client.ResendEmailVerificationWithApplicationTemplateAsync(applicationId, email).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<VerifyRegistrationResponse> ResendRegistrationVerification(string email, Guid? applicationId) {
      return client.ResendRegistrationVerificationAsync(email, applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ActionResponse> RetrieveAction(Guid? actionId) {
      return client.RetrieveActionAsync(actionId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ActionResponse> RetrieveActions(Guid? userId) {
      return client.RetrieveActionsAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ActionResponse> RetrieveActionsPreventingLogin(Guid? userId) {
      return client.RetrieveActionsPreventingLoginAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ActionResponse> RetrieveActiveActions(Guid? userId) {
      return client.RetrieveActiveActionsAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> RetrieveApplication(Guid? applicationId) {
      return client.RetrieveApplicationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> RetrieveApplications() {
      return client.RetrieveApplicationsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<AuditLogResponse> RetrieveAuditLog(int? auditLogId) {
      return client.RetrieveAuditLogAsync(auditLogId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConnectorResponse> RetrieveConnector(Guid? connectorId) {
      return client.RetrieveConnectorAsync(connectorId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConnectorResponse> RetrieveConnectors() {
      return client.RetrieveConnectorsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConsentResponse> RetrieveConsent(Guid? consentId) {
      return client.RetrieveConsentAsync(consentId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConsentResponse> RetrieveConsents() {
      return client.RetrieveConsentsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<DailyActiveUserReportResponse> RetrieveDailyActiveReport(Guid? applicationId, long? start, long? end) {
      return client.RetrieveDailyActiveReportAsync(applicationId, start, end).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<EmailTemplateResponse> RetrieveEmailTemplate(Guid? emailTemplateId) {
      return client.RetrieveEmailTemplateAsync(emailTemplateId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<PreviewResponse> RetrieveEmailTemplatePreview(PreviewRequest request) {
      return client.RetrieveEmailTemplatePreviewAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<EmailTemplateResponse> RetrieveEmailTemplates() {
      return client.RetrieveEmailTemplatesAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<EventLogResponse> RetrieveEventLog(int? eventLogId) {
      return client.RetrieveEventLogAsync(eventLogId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FamilyResponse> RetrieveFamilies(Guid? userId) {
      return client.RetrieveFamiliesAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FamilyResponse> RetrieveFamilyMembersByFamilyId(Guid? familyId) {
      return client.RetrieveFamilyMembersByFamilyIdAsync(familyId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FormResponse> RetrieveForm(Guid? formId) {
      return client.RetrieveFormAsync(formId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FormFieldResponse> RetrieveFormField(Guid? fieldId) {
      return client.RetrieveFormFieldAsync(fieldId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FormFieldResponse> RetrieveFormFields() {
      return client.RetrieveFormFieldsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FormResponse> RetrieveForms() {
      return client.RetrieveFormsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<GroupResponse> RetrieveGroup(Guid? groupId) {
      return client.RetrieveGroupAsync(groupId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<GroupResponse> RetrieveGroups() {
      return client.RetrieveGroupsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IdentityProviderResponse> RetrieveIdentityProvider(Guid? identityProviderId) {
      return client.RetrieveIdentityProviderAsync(identityProviderId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IdentityProviderResponse> RetrieveIdentityProviders() {
      return client.RetrieveIdentityProvidersAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ActionResponse> RetrieveInactiveActions(Guid? userId) {
      return client.RetrieveInactiveActionsAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> RetrieveInactiveApplications() {
      return client.RetrieveInactiveApplicationsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionResponse> RetrieveInactiveUserActions() {
      return client.RetrieveInactiveUserActionsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IntegrationResponse> RetrieveIntegration() {
      return client.RetrieveIntegrationAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKey(string keyId) {
      return client.RetrieveJWTPublicKeyAsync(keyId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKeyByApplicationId(string applicationId) {
      return client.RetrieveJWTPublicKeyByApplicationIdAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<PublicKeyResponse> RetrieveJWTPublicKeys() {
      return client.RetrieveJWTPublicKeysAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<JWKSResponse> RetrieveJsonWebKeySet() {
      return client.RetrieveJsonWebKeySetAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<KeyResponse> RetrieveKey(Guid? keyId) {
      return client.RetrieveKeyAsync(keyId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<KeyResponse> RetrieveKeys() {
      return client.RetrieveKeysAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LambdaResponse> RetrieveLambda(Guid? lambdaId) {
      return client.RetrieveLambdaAsync(lambdaId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LambdaResponse> RetrieveLambdas() {
      return client.RetrieveLambdasAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LambdaResponse> RetrieveLambdasByType(LambdaType type) {
      return client.RetrieveLambdasByTypeAsync(type).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginReportResponse> RetrieveLoginReport(Guid? applicationId, long? start, long? end) {
      return client.RetrieveLoginReportAsync(applicationId, start, end).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<MonthlyActiveUserReportResponse> RetrieveMonthlyActiveReport(Guid? applicationId, long? start, long? end) {
      return client.RetrieveMonthlyActiveReportAsync(applicationId, start, end).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<OAuthConfigurationResponse> RetrieveOauthConfiguration(Guid? applicationId) {
      return client.RetrieveOauthConfigurationAsync(applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<OpenIdConfiguration> RetrieveOpenIdConfiguration() {
      return client.RetrieveOpenIdConfigurationAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<PasswordValidationRulesResponse> RetrievePasswordValidationRules() {
      return client.RetrievePasswordValidationRulesAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<PasswordValidationRulesResponse> RetrievePasswordValidationRulesWithTenantId(Guid? tenantId) {
      return client.RetrievePasswordValidationRulesWithTenantIdAsync(tenantId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<PendingResponse> RetrievePendingChildren(string parentEmail) {
      return client.RetrievePendingChildrenAsync(parentEmail).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RecentLoginResponse> RetrieveRecentLogins(int? offset, int? limit) {
      return client.RetrieveRecentLoginsAsync(offset, limit).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RefreshResponse> RetrieveRefreshTokens(Guid? userId) {
      return client.RetrieveRefreshTokensAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RegistrationResponse> RetrieveRegistration(Guid? userId, Guid? applicationId) {
      return client.RetrieveRegistrationAsync(userId, applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RegistrationReportResponse> RetrieveRegistrationReport(Guid? applicationId, long? start, long? end) {
      return client.RetrieveRegistrationReportAsync(applicationId, start, end).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<SystemConfigurationResponse> RetrieveSystemConfiguration() {
      return client.RetrieveSystemConfigurationAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<TenantResponse> RetrieveTenant(Guid? tenantId) {
      return client.RetrieveTenantAsync(tenantId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<TenantResponse> RetrieveTenants() {
      return client.RetrieveTenantsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ThemeResponse> RetrieveTheme(Guid? themeId) {
      return client.RetrieveThemeAsync(themeId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ThemeResponse> RetrieveThemes() {
      return client.RetrieveThemesAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<TotalsReportResponse> RetrieveTotalReport() {
      return client.RetrieveTotalReportAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> RetrieveUser(Guid? userId) {
      return client.RetrieveUserAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionResponse> RetrieveUserAction(Guid? userActionId) {
      return client.RetrieveUserActionAsync(userActionId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionReasonResponse> RetrieveUserActionReason(Guid? userActionReasonId) {
      return client.RetrieveUserActionReasonAsync(userActionReasonId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionReasonResponse> RetrieveUserActionReasons() {
      return client.RetrieveUserActionReasonsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionResponse> RetrieveUserActions() {
      return client.RetrieveUserActionsAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> RetrieveUserByChangePasswordId(string changePasswordId) {
      return client.RetrieveUserByChangePasswordIdAsync(changePasswordId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> RetrieveUserByEmail(string email) {
      return client.RetrieveUserByEmailAsync(email).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> RetrieveUserByLoginId(string loginId) {
      return client.RetrieveUserByLoginIdAsync(loginId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> RetrieveUserByUsername(string username) {
      return client.RetrieveUserByUsernameAsync(username).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> RetrieveUserByVerificationId(string verificationId) {
      return client.RetrieveUserByVerificationIdAsync(verificationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserCommentResponse> RetrieveUserComments(Guid? userId) {
      return client.RetrieveUserCommentsAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserConsentResponse> RetrieveUserConsent(Guid? userConsentId) {
      return client.RetrieveUserConsentAsync(userConsentId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserConsentResponse> RetrieveUserConsents(Guid? userId) {
      return client.RetrieveUserConsentsAsync(userId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> RetrieveUserInfoFromAccessToken(string encodedJWT) {
      return client.RetrieveUserInfoFromAccessTokenAsync(encodedJWT).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginReportResponse> RetrieveUserLoginReport(Guid? applicationId, Guid? userId, long? start, long? end) {
      return client.RetrieveUserLoginReportAsync(applicationId, userId, start, end).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginReportResponse> RetrieveUserLoginReportByLoginId(Guid? applicationId, string loginId, long? start, long? end) {
      return client.RetrieveUserLoginReportByLoginIdAsync(applicationId, loginId, start, end).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RecentLoginResponse> RetrieveUserRecentLogins(Guid? userId, int? offset, int? limit) {
      return client.RetrieveUserRecentLoginsAsync(userId, offset, limit).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> RetrieveUserUsingJWT(string encodedJWT) {
      return client.RetrieveUserUsingJWTAsync(encodedJWT).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<WebhookResponse> RetrieveWebhook(Guid? webhookId) {
      return client.RetrieveWebhookAsync(webhookId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<WebhookResponse> RetrieveWebhooks() {
      return client.RetrieveWebhooksAsync().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> RevokeRefreshToken(string token, Guid? userId, Guid? applicationId) {
      return client.RevokeRefreshTokenAsync(token, userId, applicationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> RevokeUserConsent(Guid? userConsentId) {
      return client.RevokeUserConsentAsync(userConsentId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<AuditLogSearchResponse> SearchAuditLogs(AuditLogSearchRequest request) {
      return client.SearchAuditLogsAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<EventLogSearchResponse> SearchEventLogs(EventLogSearchRequest request) {
      return client.SearchEventLogsAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginRecordSearchResponse> SearchLoginRecords(LoginRecordSearchRequest request) {
      return client.SearchLoginRecordsAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to SearchUsersByIds, use that method instead.")]
    public ClientResponse<SearchResponse> SearchUsers(List<string> ids) {
      return client.SearchUsersAsync(ids).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<SearchResponse> SearchUsersByIds(List<string> ids) {
      return client.SearchUsersByIdsAsync(ids).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<SearchResponse> SearchUsersByQuery(SearchRequest request) {
      return client.SearchUsersByQueryAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    [Obsolete("This method has been renamed to SearchUsersByQuery, use that method instead.")]
    public ClientResponse<SearchResponse> SearchUsersByQueryString(SearchRequest request) {
      return client.SearchUsersByQueryStringAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<SendResponse> SendEmail(Guid? emailTemplateId, SendRequest request) {
      return client.SendEmailAsync(emailTemplateId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> SendFamilyRequestEmail(FamilyEmailRequest request) {
      return client.SendFamilyRequestEmailAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> SendPasswordlessCode(PasswordlessSendRequest request) {
      return client.SendPasswordlessCodeAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> SendTwoFactorCode(TwoFactorSendRequest request) {
      return client.SendTwoFactorCodeAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> SendTwoFactorCodeForLogin(string twoFactorId) {
      return client.SendTwoFactorCodeForLoginAsync(twoFactorId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IdentityProviderStartLoginResponse> StartIdentityProviderLogin(IdentityProviderStartLoginRequest request) {
      return client.StartIdentityProviderLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<PasswordlessStartResponse> StartPasswordlessLogin(PasswordlessStartRequest request) {
      return client.StartPasswordlessLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LoginResponse> TwoFactorLogin(TwoFactorLoginRequest request) {
      return client.TwoFactorLoginAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> UpdateApplication(Guid? applicationId, ApplicationRequest request) {
      return client.UpdateApplicationAsync(applicationId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ApplicationResponse> UpdateApplicationRole(Guid? applicationId, Guid? roleId, ApplicationRequest request) {
      return client.UpdateApplicationRoleAsync(applicationId, roleId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConnectorResponse> UpdateConnector(Guid? connectorId, ConnectorRequest request) {
      return client.UpdateConnectorAsync(connectorId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ConsentResponse> UpdateConsent(Guid? consentId, ConsentRequest request) {
      return client.UpdateConsentAsync(consentId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<EmailTemplateResponse> UpdateEmailTemplate(Guid? emailTemplateId, EmailTemplateRequest request) {
      return client.UpdateEmailTemplateAsync(emailTemplateId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FormResponse> UpdateForm(Guid? formId, FormRequest request) {
      return client.UpdateFormAsync(formId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<FormFieldResponse> UpdateFormField(Guid? fieldId, FormFieldRequest request) {
      return client.UpdateFormFieldAsync(fieldId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<GroupResponse> UpdateGroup(Guid? groupId, GroupRequest request) {
      return client.UpdateGroupAsync(groupId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IdentityProviderResponse> UpdateIdentityProvider(Guid? identityProviderId, IdentityProviderRequest request) {
      return client.UpdateIdentityProviderAsync(identityProviderId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<IntegrationResponse> UpdateIntegrations(IntegrationRequest request) {
      return client.UpdateIntegrationsAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<KeyResponse> UpdateKey(Guid? keyId, KeyRequest request) {
      return client.UpdateKeyAsync(keyId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<LambdaResponse> UpdateLambda(Guid? lambdaId, LambdaRequest request) {
      return client.UpdateLambdaAsync(lambdaId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RegistrationResponse> UpdateRegistration(Guid? userId, RegistrationRequest request) {
      return client.UpdateRegistrationAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<SystemConfigurationResponse> UpdateSystemConfiguration(SystemConfigurationRequest request) {
      return client.UpdateSystemConfigurationAsync(request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<TenantResponse> UpdateTenant(Guid? tenantId, TenantRequest request) {
      return client.UpdateTenantAsync(tenantId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ThemeResponse> UpdateTheme(Guid? themeId, ThemeRequest request) {
      return client.UpdateThemeAsync(themeId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserResponse> UpdateUser(Guid? userId, UserRequest request) {
      return client.UpdateUserAsync(userId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionResponse> UpdateUserAction(Guid? userActionId, UserActionRequest request) {
      return client.UpdateUserActionAsync(userActionId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserActionReasonResponse> UpdateUserActionReason(Guid? userActionReasonId, UserActionReasonRequest request) {
      return client.UpdateUserActionReasonAsync(userActionReasonId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<UserConsentResponse> UpdateUserConsent(Guid? userConsentId, UserConsentRequest request) {
      return client.UpdateUserConsentAsync(userConsentId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<WebhookResponse> UpdateWebhook(Guid? webhookId, WebhookRequest request) {
      return client.UpdateWebhookAsync(webhookId, request).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> ValidateDevice(string user_code, string client_id) {
      return client.ValidateDeviceAsync(user_code, client_id).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<ValidateResponse> ValidateJWT(string encodedJWT) {
      return client.ValidateJWTAsync(encodedJWT).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> VerifyEmail(string verificationId) {
      return client.VerifyEmailAsync(verificationId).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public ClientResponse<RESTVoid> VerifyRegistration(string verificationId) {
      return client.VerifyRegistrationAsync(verificationId).GetAwaiter().GetResult();
    }
  }
}
