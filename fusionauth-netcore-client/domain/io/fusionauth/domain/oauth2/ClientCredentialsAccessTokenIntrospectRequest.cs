/*
 * Copyright (c) FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain.oauth2
{

  /**
   * Contains the parameters used to introspect an access token that was obtained via the client credentials grant.
   *
   * @author Lyle Schemmerling
   */
  public class ClientCredentialsAccessTokenIntrospectRequest {

    public string tenantId;

    public string token;

    public ClientCredentialsAccessTokenIntrospectRequest with(Action<ClientCredentialsAccessTokenIntrospectRequest> action) {
      action(this);
      return this;
    }
  }
}
