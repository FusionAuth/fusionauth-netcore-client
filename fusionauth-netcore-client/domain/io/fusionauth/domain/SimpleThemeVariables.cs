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

namespace io.fusionauth.domain
{

  /**
   * Theme object for values used in the css variables for simple themes.
   *
   * @author Lyle Schemmerling
   */
  public class SimpleThemeVariables {

    public string alertBackgroundColor;

    public string alertFontColor;

    public string backgroundImageURL;

    public string backgroundSize;

    public string borderRadius;

    public string deleteButtonColor;

    public string deleteButtonFocusColor;

    public string deleteButtonTextColor;

    public string deleteButtonTextFocusColor;

    public string errorFontColor;

    public string errorIconColor;

    public string fontColor;

    public string fontFamily;

    public bool? footerDisplay;

    public string iconBackgroundColor;

    public string iconColor;

    public string infoIconColor;

    public string inputBackgroundColor;

    public string inputIconColor;

    public string inputTextColor;

    public string linkTextColor;

    public string linkTextFocusColor;

    public string logoImageSize;

    public string logoImageURL;

    public string monoFontColor;

    public string monoFontFamily;

    public string pageBackgroundColor;

    public string panelBackgroundColor;

    public string primaryButtonColor;

    public string primaryButtonFocusColor;

    public string primaryButtonTextColor;

    public string primaryButtonTextFocusColor;

    public SimpleThemeVariables with(Action<SimpleThemeVariables> action) {
      action(this);
      return this;
    }
  }
}
