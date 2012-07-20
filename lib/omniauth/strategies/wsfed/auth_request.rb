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
          whr     = url_encode(args[:whr])

          query_string = "?wa=#{wa}&wtrealm=#{wtrealm}&wreply=#{wreply}&wctx=#{}&wct=#{wct}"

          unless whr.nil? or whr.empty?
            query_string = "#{query_string}&whr=#{whr}"
          end

          settings[:issuer] + query_string
        end

      end

    end
  end
end