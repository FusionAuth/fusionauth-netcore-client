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


using io.fusionauth.domain.api.webauthn.enums;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain {

  /**
   * A User's WebAuthnCredential. Contains all data required to complete WebAuthn authentication ceremonies.
   *
   * @author Spencer Witt
   */
  public class WebAuthnCredential {

    public CoseAlgorithmIdentifier alg;

    public string credentialId;

    public IDictionary<string, object> data;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public DateTimeOffset? lastUseInstant;

    public string publicKey;

    public int? signCount;

    public Guid? tenantId;

    public List<AuthenticatorTransport> transports;

    public Guid? userId;

    public WebAuthnCredential with(Action<WebAuthnCredential> action) {
      action(this);
      return this;
    }
  }
}
