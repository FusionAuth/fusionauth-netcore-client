/*
 * Copyright (c) 2018-2023, FusionAuth, All Rights Reserved
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


using io.fusionauth.domain.connector;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain
{

  /**
   * @author Daniel DeGroff
   */
  public class Tenant {

    public IDictionary<string, object> data;

    public TenantAccessControlConfiguration accessControlConfiguration;

    public TenantCaptchaConfiguration captchaConfiguration;

    public bool? configured;

    public List<ConnectorPolicy> connectorPolicies;

    public EmailConfiguration emailConfiguration;

    public EventConfiguration @eventConfiguration;

    public ExternalIdentifierConfiguration externalIdentifierConfiguration;

    public FailedAuthenticationConfiguration failedAuthenticationConfiguration;

    public FamilyConfiguration familyConfiguration;

    public TenantFormConfiguration formConfiguration;

    public string httpSessionMaxInactiveInterval;

    public Guid? id;

    public TenantIdentityConfiguration identityConfiguration;

    public DateTimeOffset? insertInstant;

    public string issuer;

    public JWTConfiguration jwtConfiguration;

    public TenantLambdaConfiguration lambdaConfiguration;

    public DateTimeOffset? lastUpdateInstant;

    public TenantLoginConfiguration loginConfiguration;

    public string logoutURL;

    public MaximumPasswordAge maximumPasswordAge;

    public MinimumPasswordAge minimumPasswordAge;

    public TenantMultiFactorConfiguration multiFactorConfiguration;

    public string name;

    public TenantOAuth2Configuration oauthConfiguration;

    public PasswordEncryptionConfiguration passwordEncryptionConfiguration;

    public PasswordValidationRules passwordValidationRules;

    public TenantRateLimitConfiguration rateLimitConfiguration;

    public TenantRegistrationConfiguration registrationConfiguration;

    public TenantSCIMServerConfiguration scimServerConfiguration;

    public TenantSMSConfiguration smsConfiguration;

    public TenantSSOConfiguration ssoConfiguration;

    public ObjectState state;

    public Guid? themeId;

    public TenantUserDeletePolicy userDeletePolicy;

    public TenantUsernameConfiguration usernameConfiguration;

    public TenantWebAuthnConfiguration webAuthnConfiguration;

    public Tenant with(Action<Tenant> action) {
      action(this);
      return this;
    }
  }
}
