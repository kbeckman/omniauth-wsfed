require 'erb'

module OmniAuth
  module Strategies
    class WSFed

      class AuthRequest
        include ERB::Util

        SIGNIN_PARAM = 'wsignin1.0'

        attr_reader :strategy_settings, :args

        def initialize(settings, args = {})
          raise ArgumentError.new('OmniAuth-WSFed settings cannot be nil.') if settings.nil?

          @strategy_settings  = settings
          @args               = args
        end

        def redirect_url
          if args[:whr].nil? && strategy_settings[:home_realm_discovery_path]
            strategy_settings[:home_realm_discovery_path]
          else
            wsfed_signin_request
          end
        end

        def wsfed_signin_request
          wa      = SIGNIN_PARAM
          wtrealm = url_encode(strategy_settings[:realm])
          wreply  = url_encode(strategy_settings[:reply])
          wct     = url_encode(Time.now.utc)
          whr     = url_encode(args[:whr])

          query_string = "?wa=#{wa}&wtrealm=#{wtrealm}&wreply=#{wreply}&wctx=#{}&wct=#{wct}"

          unless whr.nil? or whr.empty?
            query_string = "#{query_string}&whr=#{whr}"
          end

          strategy_settings[:issuer] + query_string
        end

      end

    end
  end
end