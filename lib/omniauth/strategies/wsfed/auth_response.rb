require "time"
require "hashie"
require "rexml/xpath"

module OmniAuth
  module Strategies
    class WSFed

      class AuthResponse

        WS_TRUST = "http://schemas.xmlsoap.org/ws/2005/02/trust"
        WS_UTILITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        WS_POLICY = "http://schemas.xmlsoap.org/ws/2004/09/policy"

        ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
        PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
        DSIG      = "http://www.w3.org/2000/09/xmldsig#"

        attr_accessor :options, :response, :settings

        def initialize(response, settings, options = {})
          raise ArgumentError.new("Response cannot be nil.") if response.nil?
          raise ArgumentError.new("WSFed settings cannot be nil.") if settings.nil?

          self.options  = options
          self.response = response
          self.settings = settings
        end


        # TODO: remove reference to SignedDocument (document) and move it to validation
        # use response variable instead...
        def document
          @document ||= OmniAuth::Strategies::WSFed::XMLSecurity::SignedDocument.new(response)
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
        # token abastraction...

        def issuer
          @issuer ||= begin
            REXML::XPath.first(document, '//Assertion/Issuer').text
          end
        end

        def claims
          @attr_statements ||= begin
            stmt_element = REXML::XPath.first(document, "//Assertion/AttributeStatement")
            return {} if stmt_element.nil?

            {}.tap do |result|
              stmt_element.elements.each do |attr_element|
                name  = attr_element.attributes["Name"]

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





        def validation_error(message)
          raise OmniAuth::Strategies::WSFed::ValidationError.new(message)
        end

        def validate(soft = true)
          validate_response_state(soft) &&
              validate_conditions(soft)     &&
              document.validate(get_fingerprint, soft)
        end

        def validate_response_state(soft = true)
          if response.empty?
            return soft ? false : validation_error("Blank response")
          end

          if settings.nil?
            return soft ? false : validation_error("No settings on response")
          end

          if settings[:idp_cert_fingerprint].nil? && settings[:idp_cert].nil?
            return soft ? false : validation_error("No fingerprint or certificate on settings")
          end

          true
        end

        def get_fingerprint
          if settings[:idp_cert_fingerprint]
            settings[:idp_cert_fingerprint]
          else
            cert = OpenSSL::X509::Certificate.new(settings[:idp_cert].gsub(/^ +/, ''))
            Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
          end
        end

        def validate_conditions(soft = true)
          return true if conditions.nil?
          return true if options[:skip_conditions]

          if not_before = parse_time(conditions, "NotBefore")
            if Time.now.utc < not_before
              return soft ? false : validation_error("Current time is earlier than NotBefore condition")
            end
          end

          if not_on_or_after = parse_time(conditions, "NotOnOrAfter")
            if Time.now.utc >= not_on_or_after
              return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
            end
          end

          true
        end

        def parse_time(node, attribute)
          if node && node.attributes[attribute]
            Time.parse(node.attributes[attribute])
          end
        end

        def signed_element_id
          doc_id = document.signed_element_id
          doc_id[1, doc_id.size]
        end
      end

    end
  end
end