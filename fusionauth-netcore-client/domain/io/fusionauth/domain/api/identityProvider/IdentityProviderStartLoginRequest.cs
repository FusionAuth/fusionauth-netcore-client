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


using io.fusionauth.domain.api;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.api.identityProvider
{

  /**
   * @author Daniel DeGroff
   */
  public class IdentityProviderStartLoginRequest: BaseLoginRequest {

    public IDictionary<string, string> data;

    public Guid? identityProviderId;

    public string loginId;

    public IDictionary<string, object> state;

    public IdentityProviderStartLoginRequest with(Action<IdentityProviderStartLoginRequest> action) {
      action(this);
      return this;
    }
  }
}
