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


using io.fusionauth.domain.email;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.api.email
{

  /**
   * @author Daniel DeGroff
   */
  public class SendRequest {

    public Guid? applicationId;

    public List<string> bccAddresses;

    public List<string> ccAddresses;

    public List<string> preferredLanguages;

    public IDictionary<string, object> requestData;

    public List<EmailAddress> toAddresses;

    public List<Guid> userIds;

    public SendRequest with(Action<SendRequest> action) {
      action(this);
      return this;
    }
  }
}
