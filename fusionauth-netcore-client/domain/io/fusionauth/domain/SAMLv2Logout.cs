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


using System.Collections.Generic;
using System;

namespace io.fusionauth.domain {

  public class SAMLv2Logout {

    public SAMLLogoutBehavior behavior;

    public Guid? defaultVerificationKeyId;

    public Guid? keyId;

    public bool? requireSignedRequests;

    public SAMLv2SingleLogout singleLogout;

    public CanonicalizationMethod xmlSignatureC14nMethod;

    public SAMLv2Logout with(Action<SAMLv2Logout> action) {
      action(this);
      return this;
    }
  }
}
