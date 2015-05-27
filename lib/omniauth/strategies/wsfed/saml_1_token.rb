module OmniAuth
  module Strategies
    class WSFed
      class SAML1Token

        attr_accessor :document

        def initialize(document)
          @document = document
        end

        def audience
          applies_to = REXML::XPath.first(document, '//t:RequestSecurityTokenResponse/wsp:AppliesTo', { 't' => WS_TRUST, 'wsp' => WS_POLICY })
          REXML::XPath.first(applies_to, '//wsa:EndpointReference/wsa:Address').text
        end

        def issuer
          REXML::XPath.first(document, '//saml:Assertion').attributes['Issuer']
        end

        def claims
          stmt_element = REXML::XPath.first(document, '//saml:Assertion/saml:AttributeStatement')

          return {} if stmt_element.nil?

          {}.tap do |result|
            stmt_element.each_element('saml:Attribute') do |attr_element|
              name  = attr_element.attributes['AttributeName']

              if attr_element.elements.count > 1
                value = []
                attr_element.elements.each { |element| value << element.text }
              else
                value = attr_element.elements.first.text.to_s.lstrip.rstrip
              end

              result[name] = value
            end
          end
        end

      end
    end
  end
end
