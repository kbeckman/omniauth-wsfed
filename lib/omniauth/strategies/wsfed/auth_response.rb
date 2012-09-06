require "time"
require "hashie"

module OmniAuth
  module Strategies
    class WSFed

      class AuthResponse

        ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
        PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
        DSIG      = "http://www.w3.org/2000/09/xmldsig#"

        attr_accessor :options, :response, :document, :settings

        def initialize(response, settings, options = {})
          raise ArgumentError.new("Response cannot be nil.") if response.nil?
          raise ArgumentError.new("WSFed settings cannot be nil.") if settings.nil?

          self.options  = options
          self.response = response
          self.settings = settings
          self.document = OmniAuth::Strategies::WSFed::XMLSecurity::SignedDocument.new(response)
        end

        def valid?
          validate(soft = true)
        end

        def validate!
          validate(soft = false)
        end

        # The value of the user identifier as defined by the id_claim setting...
        def name_id
          @name_id ||= begin
            attributes.has_key?(settings[:id_claim]) ? attributes.fetch(settings[:id_claim]) : nil
          end
        end

        # A hash of all the claims provided by the response.
        def attributes
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

        # When this user session should expire at latest
        def session_expires_at
          @expires_at ||= begin
            node = xpath("/p:Response/a:Assertion/a:AuthnStatement")
            parse_time(node, "SessionNotOnOrAfter")
          end
        end

        # Conditions (if any) for the assertion to run
        def conditions
          @conditions ||= begin
            xpath("/p:Response/a:Assertion[@ID='#{signed_element_id}']/a:Conditions")
          end
        end

      private

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

        #def strip(string)
        #  return string unless string
        #  string.gsub(/^\s+/, '').gsub(/\s+$/, '')
        #end

        def xpath(path)
          #REXML::XPath.first(document, path, { "p" => PROTOCOL, "a" => ASSERTION })
          REXML::XPath.first(document, path, { "saml" => ASSERTION })
        end

        def signed_element_id
          doc_id = document.signed_element_id
          doc_id[1, doc_id.size]
        end
      end

    end
  end
end