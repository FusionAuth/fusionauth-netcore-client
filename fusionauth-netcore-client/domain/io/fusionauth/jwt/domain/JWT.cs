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


using Newtonsoft.Json;
using io.fusionauth.converters;
using System.Collections.Generic;
using System;

namespace io.fusionauth.jwt.domain
{

  /**
   * JSON Web Token (JWT) as defined by RFC 7519.
   * <pre>
   * From RFC 7519 Section 1. Introduction:
   *    The suggested pronunciation of JWT is the same as the English word "jot".
   * </pre>
   * The JWT is not Thread-Safe and should not be re-used.
   *
   * @author Daniel DeGroff
   */
  public class JWT {

    public object aud;

    [JsonConverter(typeof(DateTimeOffsetSecondsConverter))]
    public DateTimeOffset? exp;

    [JsonConverter(typeof(DateTimeOffsetSecondsConverter))]
    public DateTimeOffset? iat;

    public string iss;

    [JsonConverter(typeof(DateTimeOffsetSecondsConverter))]
    public DateTimeOffset? nbf;

    public dynamic this[string claim] {
      get => otherClaims[claim];
      set => otherClaims[claim] = value;
    }

    [JsonExtensionData]
    private readonly Dictionary<string, dynamic> otherClaims = new Dictionary<string, dynamic>();

    public string sub;

    public string jti;

    public JWT with(Action<JWT> action) {
      action(this);
      return this;
    }
  }
}
