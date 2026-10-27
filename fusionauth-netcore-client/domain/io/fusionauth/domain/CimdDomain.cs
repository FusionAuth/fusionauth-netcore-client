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


using io.fusionauth.domain.oauth2;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain
{

  /**
   * A CIMD (Client ID Metadata Document) domain. Represents one trusted {@code client_id} domain (or the wildcard {@code *} for open mode)
   * within a tenant.
   */
  public class CimdDomain {

    public IDictionary<string, object> data;

    public bool? allowLocalhostRedirectUris;

    public List<string> authorizedResourceUris;

    public OAuthScopeConsentMode consentMode;

    public bool? debug;

    public string domain;

    public int? gracePeriodInSeconds;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public Guid? jwtPopulateLambdaId;

    public DateTimeOffset? lastUpdateInstant;

    public int? maxCacheTtlInSeconds;

    public string name;

    public ProvidedScopePolicy providedScopePolicy;

    public Guid? registrationLambdaId;

    public List<CimdDomainOAuthScope> scopes;

    public Guid? tenantId;

    public CimdDomain with(Action<CimdDomain> action) {
      action(this);
      return this;
    }
  }
}
