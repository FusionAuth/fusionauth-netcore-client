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


using io.fusionauth.converters.helpers;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.provider
{

  /**
   * @author Lyle Schemmerling
   */
  public class BaseSAMLv2IdentityProvider<D>: BaseIdentityProvider<D> {

    public SAMLv2AssertionDecryptionConfiguration assertionDecryptionConfiguration;

    public string emailClaim;

    public Guid? keyId;

    public string uniqueIdClaim;

    public bool? useNameIdForEmail;

    public string usernameClaim;

    public BaseSAMLv2IdentityProvider<D> with(Action<BaseSAMLv2IdentityProvider<D>> action) {
      action(this);
      return this;
    }
  }
}
