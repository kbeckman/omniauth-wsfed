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
          signed_document = OmniAuth::Strategies::WSFed::XMLSecurity::SignedDocument.new(response)
          signed_document.validate(get_fingerprint, false)

          response  = OmniAuth::Strategies::WSFed::AuthResponse.new(request.params['wresult'], options)
          validator = OmniAuth::Strategies::WSFed::CallbackValidator.new(response, options)

          validator.validate!

          @name_id  = response.name_id
          @claims   = response.attributes

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
          Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
        end
      end

    end
  end
end

OmniAuth.config.add_camelization 'wsfed', 'WSFed'