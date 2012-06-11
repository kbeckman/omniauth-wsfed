require 'omniauth'

module OmniAuth
  module Strategies

    class WSFed
      include OmniAuth::Strategy

      autoload :AuthRequest,      'omniauth/strategies/wsfed/auth_request'
      autoload :AuthResponse,     'omniauth/strategies/wsfed/auth_response'
      autoload :ValidationError,  'omniauth/strategies/wsfed/validation_error'
      autoload :XMLSecurity,      'omniauth/strategies/wsfed/xml_security'

      #Issues WS-Federation redirect for authentication...
      def request_phase
        request = OmniAuth::Strategies::WSFed::AuthRequest.new
        redirect(request.create(options, :whr => @request.params['whr']))
      end

      #Parse SAML token...
      def callback_phase
        begin
          response = OmniAuth::Strategies::WSFed::AuthResponse.new(request.params['wresult'])
          response.settings = options

          @name_id  = response.name_id
          @attributes = response.attributes

          return fail!(:invalid_ticket, 'Invalid SAML Token') if @name_id.nil? || @name_id.empty? || !response.valid?
          super
        rescue ArgumentError => e
          fail!(:invalid_ticket, 'Invalid WSFed Response')
        end
      end

      uid { @name_id }

      info do
        {
            :name  => @attributes[:name],
            :email => @attributes[:email] || @attributes[:mail],
            :first_name => @attributes[:first_name] || @attributes[:firstname],
            :last_name => @attributes[:last_name] || @attributes[:lastname]
        }
      end

      extra { { :raw_info => @attributes } }

    end
  end
end

OmniAuth.config.add_camelization 'wsfed', 'WSFed'