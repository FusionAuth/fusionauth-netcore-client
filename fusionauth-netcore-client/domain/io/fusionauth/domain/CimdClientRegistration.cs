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
   * A CIMD (Client ID Metadata Document) client registration. Represents one concrete, fetched {@code client_id} URL registered against
   * a {@link CimdDomain}.
   */
  public class CimdClientRegistration {

    public IDictionary<string, object> data;

    public DateTimeOffset? cacheExpirationInstant;

    public Guid? cimdDomainId;

    public string clientIdUrl;

    public string clientName;

    public string clientUri;

    public DateTimeOffset? graceExpirationInstant;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public Guid? jwtPopulateLambdaId;

    public DateTimeOffset? lastUpdateInstant;

    public IDictionary<string, CimdClientRegistrationResourceOverride> overridesByResource;

    public List<string> redirectUris;

    public Guid? tenantId;

    public CimdClientRegistrationState state;

    public CimdClientRegistration with(Action<CimdClientRegistration> action) {
      action(this);
      return this;
    }
  }
}
