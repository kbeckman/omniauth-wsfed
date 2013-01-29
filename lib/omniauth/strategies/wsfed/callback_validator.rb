module OmniAuth
  module Strategies
    class WSFed

      class CallbackValidator

        attr_accessor :auth_response, :wsfed_settings

        ISSUER_MISMATCH     = 'AuthN token issuer does not match configured issuer.'
        AUDIENCE_MISMATCH   = 'AuthN token audience does not match configured realm.'
        FUTURE_CREATED_AT   = 'AuthN token created timestamp occurs in the future.'
        TOKEN_EXPIRED       = 'AuthN token has expired.'
        NO_CLAIMS           = 'AuthN token contains no claims.'
        NO_USER_IDENTIFIER  = 'AuthN token contains no user identifier. Verify that configured :id_claim setting is correct.'

        def initialize(auth_response, wsfed_settings)
          self.auth_response  = auth_response
          self.wsfed_settings = wsfed_settings
        end

        def validate!
          raise OmniAuth::Strategies::WSFed::ValidationError.new(ISSUER_MISMATCH) unless
            auth_response.issuer == wsfed_settings[:issuer]

          raise OmniAuth::Strategies::WSFed::ValidationError.new(AUDIENCE_MISMATCH) unless
              auth_response.audience == wsfed_settings[:realm]

          raise OmniAuth::Strategies::WSFed::ValidationError.new(FUTURE_CREATED_AT) unless
              auth_response.created_at < Time.now.utc

          raise OmniAuth::Strategies::WSFed::ValidationError.new(TOKEN_EXPIRED) unless
              auth_response.expires_at > Time.now.utc

          if auth_response.claims.nil? || auth_response.claims.empty?
            raise OmniAuth::Strategies::WSFed::ValidationError.new(NO_CLAIMS)
          end

          if auth_response.name_id.nil? || auth_response.name_id.empty?
            raise OmniAuth::Strategies::WSFed::ValidationError.new(NO_USER_IDENTIFIER)
          end

          true
        end


        private


        def get_fingerprint
          if settings[:idp_cert_fingerprint]
            settings[:idp_cert_fingerprint]
          else
            cert = OpenSSL::X509::Certificate.new(settings[:idp_cert].gsub(/^ +/, ''))
            Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
          end
        end

      end

    end
  end
end