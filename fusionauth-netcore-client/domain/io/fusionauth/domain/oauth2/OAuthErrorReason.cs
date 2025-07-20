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

  public enum OAuthErrorReason {
        auth_code_not_found, 
        access_token_malformed, 
        access_token_expired, 
        access_token_unavailable_for_processing, 
        access_token_failed_processing, 
        access_token_invalid, 
        access_token_required, 
        refresh_token_not_found, 
        refresh_token_type_not_supported, 
        invalid_client_id, 
        invalid_user_credentials, 
        invalid_grant_type, 
        invalid_origin, 
        invalid_origin_opaque, 
        invalid_pkce_code_verifier, 
        invalid_pkce_code_challenge, 
        invalid_pkce_code_challenge_method, 
        invalid_redirect_uri, 
        invalid_response_mode, 
        invalid_response_type, 
        invalid_id_token_hint, 
        invalid_post_logout_redirect_uri, 
        invalid_device_code, 
        invalid_user_code, 
        invalid_additional_client_id, 
        invalid_target_entity_scope, 
        invalid_entity_permission_scope, 
        invalid_user_id, 
        invalid_tenant_id, 
        grant_type_disabled, 
        missing_client_id, 
        missing_client_secret, 
        missing_code, 
        missing_code_challenge, 
        missing_code_verifier, 
        missing_device_code, 
        missing_grant_type, 
        missing_redirect_uri, 
        missing_refresh_token, 
        missing_response_type, 
        missing_token, 
        missing_user_code, 
        missing_user_id, 
        missing_verification_uri, 
        missing_tenant_id, 
        login_prevented, 
        not_licensed, 
        user_code_expired, 
        user_expired, 
        user_locked, 
        user_not_found, 
        client_authentication_missing, 
        invalid_client_authentication_scheme, 
        invalid_client_authentication, 
        client_id_mismatch, 
        change_password_administrative, 
        change_password_breached, 
        change_password_expired, 
        change_password_validation, 
        unknown, 
        missing_required_scope, 
        unknown_scope, 
        consent_canceled
  }
}
