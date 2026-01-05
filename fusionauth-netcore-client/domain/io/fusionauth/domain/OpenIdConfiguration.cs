/*
 * Copyright (c) 2018-2026, FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain
{

  /**
   * OpenID Connect Configuration as described by the <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
   * Provider Metadata</a>.
   *
   * @author Daniel DeGroff
   */
  public class OpenIdConfiguration {

    public string authorization_endpoint;

    public bool? backchannel_logout_supported;

    public List<string> claims_supported;

    public string device_authorization_endpoint;

    public string end_session_endpoint;

    public bool? frontchannel_logout_supported;

    public List<string> grant_types_supported;

    public List<string> id_token_signing_alg_values_supported;

    public string issuer;

    public string jwks_uri;

    public List<string> response_modes_supported;

    public List<string> response_types_supported;

    public List<string> scopes_supported;

    public List<string> subject_types_supported;

    public string token_endpoint;

    public List<string> token_endpoint_auth_methods_supported;

    public string userinfo_endpoint;

    public List<string> userinfo_signing_alg_values_supported;

    public OpenIdConfiguration with(Action<OpenIdConfiguration> action) {
      action(this);
      return this;
    }
  }
}
