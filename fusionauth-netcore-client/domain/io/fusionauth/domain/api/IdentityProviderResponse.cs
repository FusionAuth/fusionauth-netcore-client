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
using io.fusionauth.converters.helpers;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.api {

  /**
   * @author Daniel DeGroff
   */
  public class IdentityProviderResponse {

    // Due to c#'s lack of generics we have to use an empty interface for this.
    // The concrete classes all implement BaseIdentityProvider
    // This also allows for serialization to and from json
    public IdentityProvider identityProvider;

    // Due to c#'s lack of generics we have to use an empty interface for this.
    // The concrete classes all implement BaseIdentityProvider
    // This also allows for serialization to and from json
    public List<IdentityProvider> identityProviders;

    public IdentityProviderResponse with(Action<IdentityProviderResponse> action) {
      action(this);
      return this;
    }
  }
}
