# OmniAuth WS-Fed #

[![Gem Version](https://badge.fury.io/rb/omniauth-wsfed.png)](http://badge.fury.io/rb/omniauth-wsfed)
[![Code Climate](https://codeclimate.com/github/kbeckman/omniauth-wsfed.png)](https://codeclimate.com/github/kbeckman/omniauth-wsfed)
[![Build Status](https://travis-ci.org/kbeckman/omniauth-wsfed.png?branch=development)](https://travis-ci.org/kbeckman/omniauth-wsfed)

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

* `:issuer_name` - The URI name of your Identity Provider (IdP). **Required**

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
posted. Defaults to the OmniAuth callback URL. **Optional**

* `:id_claim` - Name of the authentication claim that you want to use as OmniAuth's
**uid** property.

* `:saml_version` - The version of SAML tokens. **Defaults to 2**.


## Authors and Credits ##

Authored by [Keith Beckman](https://github.com/kbeckman).

Special thanks to the developers of the following projects from which I borrowed from for omniauth-wsfed:

* [PracticallyGreen / omniauth-saml](https://github.com/PracticallyGreen/omniauth-saml)
* [onelogin / ruby-saml](https://github.com/onelogin/ruby-saml)
