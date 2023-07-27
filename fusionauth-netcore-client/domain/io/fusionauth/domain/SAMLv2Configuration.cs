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


using io.fusionauth.domain.provider;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain {

  public class SAMLv2Configuration: Enableable {

    public SAMLv2AssertionEncryptionConfiguration assertionEncryptionConfiguration;

    public string audience;

    public List<string> authorizedRedirectURLs;

    public bool? debug;

    public Guid? defaultVerificationKeyId;

    public SAMLv2IdPInitiatedLoginConfiguration initiatedLogin;

    public string issuer;

    public Guid? keyId;

    public LoginHintConfiguration loginHintConfiguration;

    public SAMLv2Logout logout;

    public string logoutURL;

    public bool? requireSignedRequests;

    public CanonicalizationMethod xmlSignatureC14nMethod;

    public XMLSignatureLocation xmlSignatureLocation;

    public string callbackURL;

    public SAMLv2Configuration with(Action<SAMLv2Configuration> action) {
      action(this);
      return this;
    }
  }
}
