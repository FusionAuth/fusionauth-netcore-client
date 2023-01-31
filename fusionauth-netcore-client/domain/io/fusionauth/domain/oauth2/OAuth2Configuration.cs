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

namespace io.fusionauth.domain.oauth2 {

  /**
   * @author Daniel DeGroff
   */
  public class OAuth2Configuration {

    public List<string> authorizedOriginURLs;

    public List<string> authorizedRedirectURLs;

    public Oauth2AuthorizedURLValidationPolicy authorizedURLValidationPolicy;

    public ClientAuthenticationPolicy clientAuthenticationPolicy;

    public string clientId;

    public string clientSecret;

    public bool? debug;

    public string deviceVerificationURL;

    public List<GrantType> enabledGrants;

    public bool? generateRefreshTokens;

    public LogoutBehavior logoutBehavior;

    public string logoutURL;

    public ProofKeyForCodeExchangePolicy proofKeyForCodeExchangePolicy;

    public bool? requireClientAuthentication;

    public bool? requireRegistration;

    public OAuth2Configuration with(Action<OAuth2Configuration> action) {
      action(this);
      return this;
    }
  }
}
