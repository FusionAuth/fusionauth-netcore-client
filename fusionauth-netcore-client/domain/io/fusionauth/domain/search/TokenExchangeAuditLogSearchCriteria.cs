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


using io.fusionauth.domain;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.search
{

  /**
   * Search criteria for the token exchange audit log. Filterable on exactly {@code tenantId}, {@code exchangerClientId}, {@code outcome},
   * and an exchange instant range — no other fields, per the ARC decision to limit the index count on this table.
   */
  public class TokenExchangeAuditLogSearchCriteria: BaseSearchCriteria {

    public DateTimeOffset? end;

    public Guid? exchangerClientId;

    public TokenExchangeOutcome? outcome;

    public DateTimeOffset? start;

    public Guid? tenantId;

    public TokenExchangeAuditLogSearchCriteria with(Action<TokenExchangeAuditLogSearchCriteria> action) {
      action(this);
      return this;
    }
  }
}
