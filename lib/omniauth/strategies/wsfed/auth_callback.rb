require 'time'
require 'hashie'
require 'rexml/xpath'

module OmniAuth
  module Strategies
    class WSFed

      class AuthCallback

        WS_TRUST    = 'http://schemas.xmlsoap.org/ws/2005/02/trust'
        WS_UTILITY  = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
        WS_POLICY   = 'http://schemas.xmlsoap.org/ws/2004/09/policy'

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
          @document ||= OmniAuth::Strategies::WSFed::XMLSecurity::SignedDocument.new(raw_callback)
        end


        # WS-Trust Envelope and WS* Element Values

        def audience
          @audience ||= begin
            applies_to = REXML::XPath.first(document, '//t:RequestSecurityTokenResponse/wsp:AppliesTo', { 't' => WS_TRUST, 'wsp' => WS_POLICY })
            REXML::XPath.first(applies_to, '//EndpointReference/Address').text
          end
        end

        def created_at
          Time.parse(REXML::XPath.first(wstrust_lifetime, '//wsu:Created', { 'wsu' => WS_UTILITY }).text)
        end

        def expires_at
          Time.parse(REXML::XPath.first(wstrust_lifetime, '//wsu:Expires', { 'wsu' => WS_UTILITY }).text)
        end


        # SAML 2.0 Assertion [Token] Values
        # Note: If/When future development warrants additional token types, these items should be refactored into a
        # token abstraction...

        def issuer
          @issuer ||= begin
            REXML::XPath.first(document, '//Assertion/Issuer').text
          end
        end

        def claims
          @attr_statements ||= begin
            stmt_element = REXML::XPath.first(document, '//Assertion/AttributeStatement')
            return {} if stmt_element.nil?

            {}.tap do |result|
              stmt_element.elements.each do |attr_element|
                name  = attr_element.attributes['Name']

                if attr_element.elements.count > 1
                  value = []
                  attr_element.elements.each { |element| value << element.text }
                else
                  value = attr_element.elements.first.text.lstrip.rstrip
                end

                result[name] = value
              end
            end
          end
        end
        alias :attributes :claims

        # The value of the user identifier as defined by the id_claim configuration setting...
        def name_id
          @name_id ||= begin
            claims.has_key?(settings[:id_claim]) ? claims.fetch(settings[:id_claim]) : nil
          end
        end


      private


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