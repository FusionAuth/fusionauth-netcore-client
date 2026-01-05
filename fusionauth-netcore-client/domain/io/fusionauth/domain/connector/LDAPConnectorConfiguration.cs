/*
 * Copyright (c) FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain.connector
{

  /**
   * Models an LDAP connector.
   *
   * @author Trevor Smith
   */
  public class LDAPConnectorConfiguration: BaseConnectorConfiguration {

    public string authenticationURL;

    public string baseStructure;

    public int? connectTimeout;

    public string identifyingAttribute;

    public LambdaConfiguration lambdaConfiguration;

    public string loginIdAttribute;

    public int? readTimeout;

    public List<string> requestedAttributes;

    public LDAPSecurityMethod securityMethod;

    public string systemAccountDN;

    public string systemAccountPassword;

    public LDAPConnectorConfiguration with(Action<LDAPConnectorConfiguration> action) {
      action(this);
      return this;
    }
  }
}
