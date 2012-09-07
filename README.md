# OmniAuth WS-Fed #

#### This gem is currently under construction... Expect an official v1 release by the the end of July 2012. ####

The OmniAuth-WSFed authentication strategy can be used with the following technologies
under scenarios requiring the [WS-Federation protocol](﻿http://msdn.microsoft.com/en-us/library/bb498017.aspx)
for authentication. These services are typically used for Identity Federation and Single
Sign-On across large organizations or authentication domains.

* [Windows Azure ACS](http://msdn.microsoft.com/en-us/library/windowsazure/gg429786.aspx)
* [ADFS 2.0](http://msdn.microsoft.com/en-us/magazine/ee335705.aspx)
* Corporate Secure Token Servers (STSs)


## Installation ##

Add this line to your application's Gemfile:
```ruby
    gem 'omniauth-wsfed'
```

And then execute:

    $ bundle install

Or install it globally as:

    $ gem install omniauth-wsfed


## Configuration ##

Use the WSFed strategy as a middleware in your application:

```ruby
require 'omniauth'

use OmniAuth::Strategies::WSFed,
  :issuer_name           => "http://your-azure-acs-namespace.accesscontrol.windows.net",
  :issuer                => "https://your-azure-acs-namespace.accesscontrol.windows.net/v2/wsfederation",
  :realm                 => "http://my.relyingparty/realm",
  :reply                 => "http://localhost:3000/auth/wsfed/callback",
  :id_claim              => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  :idp_cert_fingerprint  => "FC96D2983…"
```

or in your Rails application:

in `Gemfile`:

```ruby
gem 'omniauth-wsfed'
```

and in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do

  provider :wsfed,
    :issuer_name           => "http://your-azure-acs-namespace.accesscontrol.windows.net",
    :issuer                => "https://your-azure-acs-namespace.accesscontrol.windows.net/v2/wsfederation",
    :realm                 => "http://my.relyingparty/realm",
    :reply                 => "http://localhost:3000/auth/wsfed/callback",
    :id_claim              => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    :idp_cert_fingerprint  => "FC96D2983…"

end
```


## Configuration Options ##

* `:issuer_name` - The name of your Identity Provider (IdP). This option is not required,
but can be a nice way to differentiate your IdP configurations if you are testing with
multiple providers in multiple enviornments. **Optional**

* `:issuer` - The IdP web endpoint (URL) to which the authentication request should be
sent. **Required**.

* `:idp_cert_fingerprint` - The SHA1 fingerprint of the IdP's signing certificate
(e.g. "90:CC:16:F0:8D:…"). This is provided by the IdP when setting up the trust
relationship. This option or `:idp_cert` must be present.

* `:idp_cert` - The IdP's certificate in PEM format. This option or
`:idp_cert_fingerprint` must be present.

* `:realm` - Your site's security realm. This is a URI defining the realm to which the
IdP must issue a secure token. **Required**

* `:reply` - The reply-to URL in your application for which a WSFed response should be
posted. **Required**

* `:id_claim` - Name of the authentication claim that you want to use as OmniAuth's
**uid** property.


## Authors and Credits ##

Authored by [Keith Beckman](https://github.com/kbeckman).

Special thanks to the developers of the following projects from which I borrowed from for omniauth-wsfed:

* [PracticallyGreen / omniauth-saml](https://github.com/PracticallyGreen/omniauth-saml)
* [onelogin / ruby-saml](https://github.com/onelogin/ruby-saml)


## License ##

Copyright (c) 2011-2012 Keith Beckman, [Coding4StreetCred.com](http://www.coding4streetcred.com/blog)
All rights reserved. Released under the MIT license.

Portions Copyright (c) 2007 Sun Microsystems Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
