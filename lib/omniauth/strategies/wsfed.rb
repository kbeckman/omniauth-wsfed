require 'omniauth'

module OmniAuth
  module Strategies

    class WSFed
      include OmniAuth::Strategy

      autoload :AuthRequest,        'omniauth/strategies/wsfed/auth_request'
      autoload :AuthResponse,       'omniauth/strategies/wsfed/auth_response'
      autoload :CallbackValidator,  'omniauth/strategies/wsfed/callback_validator'
      autoload :ValidationError,    'omniauth/strategies/wsfed/validation_error'
      autoload :XMLSecurity,        'omniauth/strategies/wsfed/xml_security'

      # Issues passive WS-Federation redirect for authentication...
      def request_phase
        whr = @request.params['whr']

        if !whr.nil?
          request = OmniAuth::Strategies::WSFed::AuthRequest.new
          redirect(request.create(options, :whr => whr))
        elsif !options[:home_realm_discovery_path].nil?
          redirect(options[:home_realm_discovery_path])
        else
          request = OmniAuth::Strategies::WSFed::AuthRequest.new
          redirect(request.create(options))
        end

      end

      # Parse SAML token...
      def callback_phase
        begin
          response  = OmniAuth::Strategies::WSFed::AuthResponse.new(request.params['wresult'], options)
          validator = OmniAuth::Strategies::WSFed::CallbackValidator.new(response, options)

          validator.validate!

          @name_id  = response.name_id
          @claims   = response.attributes

          # TODO: Refactor this into the callback_validator...
          return fail!(:invalid_ticket, OmniAuth::Strategies::WSFed::ValidationError('Invalid SAML Token') ) if  !response.valid?

          super

        rescue ArgumentError => e
          fail!(:invalid_response, e)
        rescue OmniAuth::Strategies::WSFed::ValidationError => e
          fail!(:invalid_authn_token, e)
        end

      end

      # OmniAuth DSL methods...
      uid { @name_id }

      info { @claims }

      extra { { :wresult => request.params['wresult'] } }

    end
  end
end

OmniAuth.config.add_camelization 'wsfed', 'WSFed'