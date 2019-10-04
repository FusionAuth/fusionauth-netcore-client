/*
 * Copyright (c) 2018, FusionAuth, All Rights Reserved
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

namespace io.fusionauth.jwt.domain {

  /**
   * Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
   *
   * @author Daniel DeGroff
   */
  public enum Algorithm {
              [EnumMember(Value = "SHA256withECDSA")]
            ES256, 
              [EnumMember(Value = "SHA384withECDSA")]
            ES384, 
              [EnumMember(Value = "SHA512withECDSA")]
            ES512, 
              [EnumMember(Value = "HmacSHA256")]
            HS256, 
              [EnumMember(Value = "HmacSHA384")]
            HS384, 
              [EnumMember(Value = "HmacSHA512")]
            HS512, 
              [EnumMember(Value = "SHA256withRSA")]
            RS256, 
              [EnumMember(Value = "SHA384withRSA")]
            RS384, 
              [EnumMember(Value = "SHA512withRSA")]
            RS512, 
              [EnumMember(Value = "None")]
            none
  }
}
