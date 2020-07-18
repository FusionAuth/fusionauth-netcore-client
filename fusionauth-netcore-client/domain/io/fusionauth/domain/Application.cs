/*
 * Copyright (c) 2018, FusionAuth, All Rights Reserved
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


using io.fusionauth.domain.provider;
using io.fusionauth.domain.oauth2;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain {

  /**
   * @author Seth Musselman
   */
  public class Application {

    public bool? active;

    public AuthenticationTokenConfiguration authenticationTokenConfiguration;

    public CleanSpeakConfiguration cleanSpeakConfiguration;

    public Dictionary<string, object> data;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public JWTConfiguration jwtConfiguration;

    public LambdaConfiguration lambdaConfiguration;

    public DateTimeOffset? lastUpdateInstant;

    public LoginConfiguration loginConfiguration;

    public string name;

    public OAuth2Configuration oauthConfiguration;

    public PasswordlessConfiguration passwordlessConfiguration;

    public RegistrationConfiguration registrationConfiguration;

    public ApplicationRegistrationDeletePolicy registrationDeletePolicy;

    public List<ApplicationRole> roles;

    public SAMLv2Configuration samlv2Configuration;

    public Guid? tenantId;

    public Guid? verificationEmailTemplateId;

    public bool? verifyRegistration;

    public Application with(Action<Application> action) {
      action(this);
      return this;
    }
  }
}
