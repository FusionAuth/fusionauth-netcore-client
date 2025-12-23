/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain.oauth2
{

  /**
   * <ul>
   * <li>Bearer Token type as defined by <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</a>.</li>
   * <li>MAC Token type as referenced by <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a> and
   * <a href="https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05">
   * Draft RFC on OAuth 2.0 Message Authentication Code (MAC) Tokens</a>
   * </li>
   * <li>DPoP Token type as defined by <a href="https://datatracker.ietf.org/doc/html/rfc9449"></li>
   * </ul>
   *
   * @author Daniel DeGroff
   */
  public enum TokenType {
        Bearer, 
        MAC, 
        DPoP
  }
}
