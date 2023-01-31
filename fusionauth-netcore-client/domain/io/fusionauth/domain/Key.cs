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


using System.Collections.Generic;
using System;

namespace io.fusionauth.domain {

  /**
   * Domain for a public key, key pair or an HMAC secret. This is used by KeyMaster to manage keys for JWTs, SAML, etc.
   *
   * @author Brian Pontarelli
   */
  public class Key {

    public KeyAlgorithm? algorithm;

    public string certificate;

    public CertificateInformation certificateInformation;

    public DateTimeOffset? expirationInstant;

    public bool? hasPrivateKey;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public string issuer;

    public string kid;

    public DateTimeOffset? lastUpdateInstant;

    public int? length;

    public string name;

    public string privateKey;

    public string publicKey;

    public string secret;

    public KeyType? type;

    public Key with(Action<Key> action) {
      action(this);
      return this;
    }
  }
}
