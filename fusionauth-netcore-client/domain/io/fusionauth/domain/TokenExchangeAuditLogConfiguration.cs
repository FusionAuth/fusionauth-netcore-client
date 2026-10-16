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
   * The system configuration for token exchange audit log data.
   * <p>
   * Deleting these entries is mandatory, so this configuration intentionally has no enabled flag. Token exchange volume can be high enough
   * that retaining entries indefinitely would grow the database without bound. Longer retention is served by ingesting the token exchange
   * webhooks into external storage.
   */
  public class TokenExchangeAuditLogConfiguration {

    public int? numberOfDaysToRetain;

    public TokenExchangeAuditLogConfiguration with(Action<TokenExchangeAuditLogConfiguration> action) {
      action(this);
      return this;
    }
  }
}
