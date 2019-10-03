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


using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.oauth2 {

  public enum OAuthErrorReason {
            auth_code_not_found, 
            access_token_malformed, 
            access_token_expired, 
            access_token_unavailable_for_processing, 
            access_token_failed_processing, 
            refresh_token_not_found, 
            invalid_client_id, 
            invalid_user_credentials, 
            invalid_grant_type, 
            invalid_origin, 
            invalid_pkce_code_verifier, 
            invalid_pkce_code_challenge, 
            invalid_pkce_code_challenge_method, 
            invalid_redirect_uri, 
            invalid_response_type, 
            invalid_id_token_hint, 
            invalid_post_logout_redirect_uri, 
            grant_type_disabled, 
            missing_client_id, 
            missing_code, 
            missing_grant_type, 
            missing_redirect_uri, 
            missing_refresh_token, 
            missing_response_type, 
            missing_token, 
            login_prevented, 
            user_expired, 
            user_locked, 
            user_not_found, 
            client_authentication_missing, 
            invalid_client_authentication_scheme, 
            invalid_client_authentication, 
            client_id_mismatch, 
            unknown
  }
}
