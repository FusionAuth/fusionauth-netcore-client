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
   * Tenant level configuration for RFC 8693 token exchange.
   */
  public class TenantTokenExchangeConfiguration: Enableable {

    public List<string> allowedIssuers;

    public bool? debug;

    public int? maxClaimDepth;

    public TokenExchangePolicyEngine policyEngine;

    public Guid? policyEngineLambdaId;

    public Guid? populateLambdaId;

    public TenantTokenExchangeConfiguration with(Action<TenantTokenExchangeConfiguration> action) {
      action(this);
      return this;
    }
  }
}
