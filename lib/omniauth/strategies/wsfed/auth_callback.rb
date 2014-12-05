require 'time'
require 'hashie'
require 'rexml/xpath'

module OmniAuth
  module Strategies
    class WSFed

      class AuthCallback

        WS_UTILITY  = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'

        attr_accessor :options, :raw_callback, :settings

        def initialize(raw_callback, settings, options = {})
          raise ArgumentError.new('Response cannot be nil.') if raw_callback.nil?
          raise ArgumentError.new('WSFed settings cannot be nil.') if settings.nil?

          self.options      = options
          self.raw_callback = raw_callback
          self.settings     = settings
        end


        # TODO: remove reference to SignedDocument (document) and move it to validation
        # use response variable instead...
        def document
          @document ||= OmniAuth::Strategies::WSFed::XMLSecurity::SignedDocument.new(raw_callback, settings)
        end


        # WS-Trust Envelope and WS* Element Values

        def audience
          @audience ||= token.audience
        end

        def created_at
          Time.parse(REXML::XPath.first(wstrust_lifetime, '//wsu:Created', { 'wsu' => WS_UTILITY }).text)
        end

        def expires_at
          Time.parse(REXML::XPath.first(wstrust_lifetime, '//wsu:Expires', { 'wsu' => WS_UTILITY }).text)
        end


        # Token Values

        def issuer
          @issuer ||= token.issuer
        end

        def claims
          @claims ||= token.claims
        end
        alias :attributes :claims

        # The value of the user identifier as defined by the id_claim configuration setting...
        def name_id
          @name_id ||= begin
            claims.has_key?(settings[:id_claim]) ? claims.fetch(settings[:id_claim]) : nil
          end
        end


      private

        def token
          @token ||= begin
            case settings[:saml_version].to_s
            when '1'
              SAML1Token.new(document)
            else
              SAML2Token.new(document)
            end
          end
        end


        # WS-Trust token lifetime element
        def wstrust_lifetime
          @wstrust_lifetime ||= begin
            REXML::XPath.first(document, '//t:RequestSecurityTokenResponse/t:Lifetime', { 't' => WS_TRUST })
          end
        end

      end

    end
  end
end