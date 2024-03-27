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

namespace io.fusionauth.domain.oauth2
{

  public enum OAuthErrorType {
        invalid_request, 
        invalid_client, 
        invalid_grant, 
        invalid_token, 
        unauthorized_client, 
        invalid_scope, 
        server_error, 
        unsupported_grant_type, 
        unsupported_response_type, 
        access_denied, 
        change_password_required, 
        not_licensed, 
        two_factor_required, 
        authorization_pending, 
        expired_token, 
        unsupported_token_type
  }
}
