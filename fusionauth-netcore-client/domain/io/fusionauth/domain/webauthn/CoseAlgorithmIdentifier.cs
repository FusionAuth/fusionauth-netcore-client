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


using System.Runtime.Serialization;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.webauthn
{

  /**
   * A number identifying a cryptographic algorithm. Values should be registered with the <a
   * href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</a>
   *
   * @author Spencer Witt
   */
  public enum CoseAlgorithmIdentifier {
        [EnumMember(Value = "SHA256withECDSA")]
        ES256, 
        [EnumMember(Value = "SHA384withECDSA")]
        ES384, 
        [EnumMember(Value = "SHA512withECDSA")]
        ES512, 
        [EnumMember(Value = "SHA256withRSA")]
        RS256, 
        [EnumMember(Value = "SHA384withRSA")]
        RS384, 
        [EnumMember(Value = "SHA512withRSA")]
        RS512, 
        [EnumMember(Value = "SHA-256")]
        PS256, 
        [EnumMember(Value = "SHA-384")]
        PS384, 
        [EnumMember(Value = "SHA-512")]
        PS512
  }
}
