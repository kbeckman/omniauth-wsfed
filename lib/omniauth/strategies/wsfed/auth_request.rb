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
          new_issuer_params = {
            wa:      SIGNIN_PARAM,
            wtrealm: url_encode(strategy_settings[:realm]),
            wreply:  url_encode(strategy_settings[:reply]),
            wct:     url_encode(Time.now.utc),
            wctx:    nil,
          }

          whr = url_encode(args[:whr])

          new_issuer_params[:whr] = whr if whr.present?

          issuer_url        = URI.parse(strategy_settings[:issuer])
          issuer_url_params = issuer_url.query.present? ? Hash[CGI.parse(issuer_url.query).map{ |key,values| [ key.to_sym, values[0] || true ] } ] : {}
          issuer_url.query  = URI.encode_www_form(issuer_url_params.merge(new_issuer_url_params))

          issuer_url.to_s
        end

      end

    end
  end
end
