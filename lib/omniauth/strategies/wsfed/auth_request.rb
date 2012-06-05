require 'erb'

module OmniAuth
  module Strategies
    class WsFed

      class AuthRequest
        include ERB::Util

        SIGNIN_PARAM = 'wsignin1.0'

        def create (settings, params = {})
          wa      = SIGNIN_PARAM
          wtrealm = url_encode(settings[:realm])
          wreply  = url_encode(settings[:reply])
          wct     = url_encode(Time.now.utc)

          query_string = "?wa=#{wa}&wtrealm=#{wtrealm}&wreply=#{wreply}&wctx=#{}&wct=#{wct}"

          # TODO: can we pull this off the current request (as well as set it in the config file)?
          query_string = "#{query_string}&whr=#{url_encode(settings[:home_realm])}" unless settings[:home_realm].empty?

          settings[:issuer] + query_string
        end

      end

    end
  end
end