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

namespace io.fusionauth.domain {

  /**
   * An action that can be executed on a user (discipline or reward potentially).
   *
   * @author Brian Pontarelli
   */
  public class UserAction {

    public bool? active;

    public Guid? cancelEmailTemplateId;

    public Guid? endEmailTemplateId;

    public Guid? id;

    public bool? includeEmailInEventJSON;

    public LocalizedStrings localizedNames;

    public Guid? modifyEmailTemplateId;

    public string name;

    public List<UserActionOption> options;

    public bool? preventLogin;

    public bool? sendEndEvent;

    public Guid? startEmailTemplateId;

    public bool? temporal;

    public TransactionType transactionType;

    public bool? userEmailingEnabled;

    public bool? userNotificationsEnabled;

    public UserAction with(Action<UserAction> action) {
      action(this);
      return this;
    }
  }
}
