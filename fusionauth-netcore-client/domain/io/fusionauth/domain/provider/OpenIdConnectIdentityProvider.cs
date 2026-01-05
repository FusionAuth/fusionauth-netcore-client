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


using io.fusionauth.converters.helpers;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.provider
{

  /**
   * @author Daniel DeGroff
   */
  public class OpenIdConnectIdentityProvider: BaseIdentityProvider<OpenIdConnectApplicationConfiguration> {

    public List<string> domains;

    public string buttonImageURL;

    public string buttonText;

    public IdentityProviderOauth2Configuration oauth2;

    public bool? postRequest;

    public OpenIdConnectIdentityProvider with(Action<OpenIdConnectIdentityProvider> action) {
      action(this);
      return this;
    }
  }
}
