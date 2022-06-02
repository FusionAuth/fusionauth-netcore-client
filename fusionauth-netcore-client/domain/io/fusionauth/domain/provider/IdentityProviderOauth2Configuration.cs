/*
 * Copyright (c) 2018-2022, FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain.provider {

  /**
   * @author Daniel DeGroff
   */
  public class IdentityProviderOauth2Configuration {

    public string authorization_endpoint;

    public ClientAuthenticationMethod clientAuthenticationMethod;

    public string client_id;

    public string client_secret;

    public string emailClaim;

    public string issuer;

    public string scope;

    public string token_endpoint;

    public string uniqueIdClaim;

    public string userinfo_endpoint;

    public string usernameClaim;

    public IdentityProviderOauth2Configuration with(Action<IdentityProviderOauth2Configuration> action) {
      action(this);
      return this;
    }
  }
}
