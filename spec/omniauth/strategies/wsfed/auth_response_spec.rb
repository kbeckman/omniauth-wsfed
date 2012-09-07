require 'spec_helper'

describe OmniAuth::Strategies::WSFed::AuthResponse do

  describe "Initialization" do

    context "with Invalid Context" do

      it "should raise an exception when response is nil" do
        expect { described_class.new(nil, {}) }.to raise_error ArgumentError
      end

      it "should raise an exception when settings are nil" do
        expect { described_class.new({}, nil) }.to raise_error ArgumentError
      end

    end

  end

  describe "Response Parsing" do

    before(:each) do
      @wsfed_settings = {
          issuer_name:  "http://identity.c4sc.com/trust/",
          issuer:       "https://identity.c4sc.com/issue/wsfed",
          realm:        "http://rp.c4sc/security_realm",
          reply:        "http://rp.c4sc/callback",
      }
    end

    context "name_id" do

      it "should load the proper value from various id_claim settings" do
        id_claims = [
            { id_claim: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", value: "kbeckman.c4sc@gmail.com" },
            { id_claim: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", value: "kbeckman.c4sc" }
        ]

        id_claims.each do |claim_setting|
          @wsfed_settings.merge!(claim_setting.select { |k,v| k == :id_claim })
          response = described_class.new(load_support_xml(:acs_example), @wsfed_settings)

          response.name_id.should == claim_setting[:value]
        end
      end

    end

    context "attributes" do

      it "should extract the authentication claims" do
        expected_claims = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" => "kbeckman.c4sc@gmail.com",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" => "kbeckman.c4sc",
            "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider" => "http://identity.c4sc.com/trust/"
        }
        response = described_class.new(load_support_xml(:acs_example), @wsfed_settings)

        response.attributes.should == expected_claims
      end

    end

  end

end
