require 'omniauth'

module OmniAuth
  module Strategies

    class WSFed
      include OmniAuth::Strategy

      autoload :AuthRequest,            'omniauth/strategies/wsfed/auth_request'
      autoload :AuthCallback,           'omniauth/strategies/wsfed/auth_callback'
      autoload :AuthCallbackValidator,  'omniauth/strategies/wsfed/auth_callback_validator'
      autoload :ValidationError,        'omniauth/strategies/wsfed/validation_error'
      autoload :XMLSecurity,            'omniauth/strategies/wsfed/xml_security'

      # Issues passive WS-Federation redirect for authentication...
      def request_phase
        auth_request = OmniAuth::Strategies::WSFed::AuthRequest.new(options, :whr => @request.params['whr'])
        redirect(auth_request.redirect_url)
      end

      # Parse SAML token...
      def callback_phase
        begin
          validate_callback_params(@request)

          wsfed_callback = request.params['wresult']

          signed_document = OmniAuth::Strategies::WSFed::XMLSecurity::SignedDocument.new(wsfed_callback)
          signed_document.validate(get_fingerprint, false)

          auth_callback   = OmniAuth::Strategies::WSFed::AuthCallback.new(wsfed_callback, options)
          validator       = OmniAuth::Strategies::WSFed::AuthCallbackValidator.new(auth_callback, options)

          validator.validate!

          @name_id  = auth_callback.name_id
          @claims   = auth_callback.attributes

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

    private

      def get_fingerprint
        if options[:idp_cert_fingerprint]
          options[:idp_cert_fingerprint]
        else
          cert = OpenSSL::X509::Certificate.new(options[:idp_cert].gsub(/^ +/, ''))
          Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(':')
        end
      end

      def validate_callback_params(request)
        if request.params['wresult'].nil? || request.params['wresult'].empty?
          raise OmniAuth::Strategies::WSFed::ValidationError.new('AuthN token (wresult) missing in callback.')
        end
      end

    end
  end
end

OmniAuth.config.add_camelization 'wsfed', 'WSFed'