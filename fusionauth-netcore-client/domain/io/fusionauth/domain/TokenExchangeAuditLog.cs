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
   * An audit record for a single token exchange attempt. Exactly one of these is written for every attempt, whether it succeeded or failed,
   * so this is the authoritative record of who exchanged what for what.
   */
  public class TokenExchangeAuditLog {

    public string actChain;

    public TokenExchangeDelegationSemantics delegationSemantics;

    public Guid? @eventId;

    public Guid? exchangerClientId;

    public string grantedAudience;

    public string grantedScope;

    public DateTimeOffset? insertInstant;

    public string intent;

    public string issuedTokenJti;

    public TokenExchangeOutcome outcome;

    public TokenExchangePolicyDecision policyDecision;

    public int? policyDecisionDurationMs;

    public TokenExchangePolicyEngine policyEngine;

    public string requestedAudience;

    public string subjectTokenIss;

    public string subjectTokenJti;

    public string subjectTokenSub;

    public string subjectTokenType;

    public SubjectTokenValidationStatus subjectTokenValidationStatus;

    public Guid? tenantId;

    public TokenExchangeAuditLog with(Action<TokenExchangeAuditLog> action) {
      action(this);
      return this;
    }
  }
}
