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


using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.reactor
{

  /**
   * @author Daniel DeGroff
   */
  public class ReactorStatus {

    public ReactorFeatureStatus advancedIdentityProviders;

    public ReactorFeatureStatus advancedLambdas;

    public ReactorFeatureStatus advancedMultiFactorAuthentication;

    public ReactorFeatureStatus advancedOAuthScopes;

    public ReactorFeatureStatus advancedOAuthScopesCustomScopes;

    public ReactorFeatureStatus advancedOAuthScopesThirdPartyApplications;

    public ReactorFeatureStatus advancedRegistration;

    public ReactorFeatureStatus applicationMultiFactorAuthentication;

    public ReactorFeatureStatus applicationThemes;

    public ReactorFeatureStatus breachedPasswordDetection;

    public ReactorFeatureStatus connectors;

    public ReactorFeatureStatus entityManagement;

    public string expiration;

    public IDictionary<string, string> licenseAttributes;

    public bool? licensed;

    public ReactorFeatureStatus scimServer;

    public ReactorFeatureStatus tenantManagerApplication;

    public ReactorFeatureStatus threatDetection;

    public ReactorFeatureStatus universalApplication;

    public ReactorFeatureStatus webAuthn;

    public ReactorFeatureStatus webAuthnPlatformAuthenticators;

    public ReactorFeatureStatus webAuthnRoamingAuthenticators;

    public ReactorStatus with(Action<ReactorStatus> action) {
      action(this);
      return this;
    }
  }
}
