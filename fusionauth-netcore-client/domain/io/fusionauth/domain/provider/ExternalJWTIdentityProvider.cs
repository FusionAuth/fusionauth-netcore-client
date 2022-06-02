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


using io.fusionauth.converters.helpers;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.provider {

  /**
   * External JWT-only identity provider.
   *
   * @author Daniel DeGroff and Brian Pontarelli
   */
  public class ExternalJWTIdentityProvider: BaseIdentityProvider<ExternalJWTApplicationConfiguration> {

    public IDictionary<string, string> claimMap;

    public Guid? defaultKeyId;

    public List<string> domains;

    public string headerKeyParameter;

    public IdentityProviderOauth2Configuration oauth2;

    public string uniqueIdentityClaim;

    public ExternalJWTIdentityProvider with(Action<ExternalJWTIdentityProvider> action) {
      action(this);
      return this;
    }
  }
}
