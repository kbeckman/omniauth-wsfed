require 'erb'

module OmniAuth
  module Strategies
    class WSFed

      class AuthRequest
        include ERB::Util

        SIGNIN_PARAM = 'wsignin1.0'

        def create (settings, args = {})
          wa      = SIGNIN_PARAM
          wtrealm = url_encode(settings[:realm])
          wreply  = url_encode(settings[:reply])
          wct     = url_encode(Time.now.utc)

          # Home Realm: check the request first, then check the strategy configuration...
          whr = args[:whr].nil? ? settings[:home_realm] : args[:whr]
          whr = url_encode(whr) unless whr.nil? or whr.empty?

          query_string = "?wa=#{wa}&wtrealm=#{wtrealm}&wreply=#{wreply}&wctx=#{}&wct=#{wct}"
          query_string = "#{query_string}&whr=#{whr}" unless whr.nil? or whr.empty?

          settings[:issuer] + query_string
        end

      end

    end
  end
end