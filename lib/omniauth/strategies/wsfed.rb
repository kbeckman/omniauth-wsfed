require 'omniauth'

module OmniAuth
  module Strategies

    class WSFed
      include OmniAuth::Strategy

      autoload :AuthRequest,      'omniauth/strategies/wsfed/auth_request'
      autoload :AuthResponse,     'omniauth/strategies/saml/auth_response'
      autoload :ValidationError,  'omniauth/strategies/saml/validation_error'
      autoload :XMLSecurity,      'omniauth/strategies/saml/xml_security'


      def request_phase
        request = OmniAuth::Strategies::WSFed::AuthRequest.new
        redirect(request.create(options))
      end

      def callback_phase

      end

    end
  end
end

OmniAuth.config.add_camelization 'wsfed', 'WSFed'