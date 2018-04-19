module OmniAuth
  module Strategies
    class WSFed
      class AuthRequest
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
          issuer_url_new_params = {
            wa:      SIGNIN_PARAM,
            wtrealm: strategy_settings[:realm],
            wreply:  strategy_settings[:reply],
            wct:     Time.now.utc,
            wctx:    nil,
          }

          new_issuer_params[:whr] = args[:whr] if args[:whr].present?

          issuer_url        = URI.parse(strategy_settings[:issuer])
          issuer_url_params = issuer_url.query.present? ? Hash[CGI.parse(issuer_url.query).map{ |key,values| [ key.to_sym, values[0] || true ] } ] : {}
          issuer_url.query  = URI.encode_www_form(issuer_url_params.merge(issuer_url_new_params))

          issuer_url.to_s
        end
      end
    end
  end
end
