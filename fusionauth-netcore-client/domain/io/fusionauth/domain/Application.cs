/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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


using io.fusionauth.domain.oauth2;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain
{

  /**
   * @author Seth Musselman
   */
  public class Application {

    public ApplicationAccessControlConfiguration accessControlConfiguration;

    public bool? active;

    public AuthenticationTokenConfiguration authenticationTokenConfiguration;

    public CleanSpeakConfiguration cleanSpeakConfiguration;

    public IDictionary<string, object> data;

    public ApplicationEmailConfiguration emailConfiguration;

    public ApplicationExternalIdentifierConfiguration externalIdentifierConfiguration;

    public ApplicationFormConfiguration formConfiguration;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public JWTConfiguration jwtConfiguration;

    public LambdaConfiguration lambdaConfiguration;

    public DateTimeOffset? lastUpdateInstant;

    public LoginConfiguration loginConfiguration;

    public ApplicationMultiFactorConfiguration multiFactorConfiguration;

    public string name;

    public OAuth2Configuration oauthConfiguration;

    public PasswordlessConfiguration passwordlessConfiguration;

    public ApplicationPhoneConfiguration phoneConfiguration;

    public RegistrationConfiguration registrationConfiguration;

    public ApplicationRegistrationDeletePolicy registrationDeletePolicy;

    public List<ApplicationRole> roles;

    public SAMLv2Configuration samlv2Configuration;

    public List<ApplicationOAuthScope> scopes;

    public ObjectState state;

    public Guid? tenantId;

    public Guid? themeId;

    public UniversalApplicationConfiguration universalConfiguration;

    public RegistrationUnverifiedOptions unverified;

    public Guid? verificationEmailTemplateId;

    public VerificationStrategy verificationStrategy;

    public bool? verifyRegistration;

    public ApplicationWebAuthnConfiguration webAuthnConfiguration;

    public Application with(Action<Application> action) {
      action(this);
      return this;
    }
  }
}
