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

namespace io.fusionauth.domain.webauthn
{

  /**
   * Allows the Relying Party to specify desired attributes of a new credential.
   *
   * @author Spencer Witt
   */
  public class PublicKeyCredentialCreationOptions {

    public AttestationConveyancePreference attestation;

    public AuthenticatorSelectionCriteria authenticatorSelection;

    public string challenge;

    public List<PublicKeyCredentialDescriptor> excludeCredentials;

    public WebAuthnRegistrationExtensionOptions extensions;

    public List<PublicKeyCredentialParameters> pubKeyCredParams;

    public PublicKeyCredentialRelyingPartyEntity rp;

    public long? timeout;

    public PublicKeyCredentialUserEntity user;

    public PublicKeyCredentialCreationOptions with(Action<PublicKeyCredentialCreationOptions> action) {
      action(this);
      return this;
    }
  }
}
