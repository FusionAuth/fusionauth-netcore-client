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

namespace io.fusionauth.domain.oauth2 {

  /**
   * Authorization Grant types as defined by the <a href="https://tools.ietf.org/html/rfc6749">The OAuth 2.0 Authorization
   * Framework - RFC 6749</a>.
   * <p>
   * Specific names as defined by <a href="https://tools.ietf.org/html/rfc7591#section-4.1">
   * OAuth 2.0 Dynamic Client Registration Protocol - RFC 7591 Section 4.1</a>
   *
   * @author Daniel DeGroff
   */
  public enum GrantType {
        [EnumMember(Value = "authorization_code")]
        authorization_code, 
        [EnumMember(Value = "implicit")]
        @implicit, 
        [EnumMember(Value = "password")]
        password, 
        [EnumMember(Value = "client_credentials")]
        client_credentials, 
        [EnumMember(Value = "refresh_token")]
        refresh_token, 
        [EnumMember(Value = "unknown")]
        unknown, 
        [EnumMember(Value = "urn:ietf:params:oauth:grant-type:device_code")]
        device_code
  }
}
