module OmniAuth
  module Strategies
    class WSFed

      class CallbackValidator

        attr_accessor :auth_response, :wsfed_settings

        def initialize(auth_response, wsfed_settings)
          self.auth_response  = auth_response
          self.wsfed_settings = wsfed_settings
        end

        def validate!
          raise OmniAuth::Strategies::WSFed::ValidationError.new("AuthN token issuer does not match configured issuer.") unless
            auth_response.issuer == wsfed_settings[:issuer]

          raise OmniAuth::Strategies::WSFed::ValidationError.new("AuthN token audience does not match configured realm.") unless
              auth_response.audience == wsfed_settings[:realm]

          if auth_response.attributes.nil? || auth_response.attributes.empty?
            raise OmniAuth::Strategies::WSFed::ValidationError.new("AuthN token contains no claims.")
          end

          if auth_response.name_id.nil? || auth_response.name_id.empty?
            raise OmniAuth::Strategies::WSFed::ValidationError.new("AuthN token contains no user identifier. Verify that configured :id_claim setting is correct.")
          end

          true
        end

      end

    end
  end
end