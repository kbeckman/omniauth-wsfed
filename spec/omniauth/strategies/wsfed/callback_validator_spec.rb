require 'spec_helper'

describe OmniAuth::Strategies::WSFed::CallbackValidator do

  describe 'Response Validation Rules' do

    let(:auth_response) { OmniAuth::Strategies::WSFed::AuthResponse.new({}, {})}

    before(:each) do
      @wsfed_settings = {
          :issuer   => "https://identity-wwf.accesscontrol.windows.net/",
          :realm    => "http://rp.wwf.com/wsfed-sample",
          :id_claim => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
      }

      @claims = {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"                => "ravishing_rick@wwf.com",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"                        => "rick.rude",
        "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider" => "http://sso.wwf.com"
      }

      auth_response.stub(:issuer).and_return(@wsfed_settings[:issuer])
      auth_response.stub(:audience).and_return(@wsfed_settings[:realm])
      auth_response.stub(:attributes).and_return(@claims)
      auth_response.stub(:name_id).and_return(@claims[@wsfed_settings[:id_claim]])
    end

    it 'should pass validation with....' do
      validator = described_class.new(auth_response, @wsfed_settings)

      validator.validate!.should == true
    end

    context 'with Invalid Response' do

      it 'should throw an exception when issuers do not match' do
        auth_response.stub(:issuer).and_return("https://c4sc-federation-nomatch.accesscontrol.windows.net/")

        validator = described_class.new(auth_response, @wsfed_settings)

        lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError
      end

      it 'should throw an exception when realm/audience do not match' do
        auth_response.stub(:audience).and_return("http://rp.c4sc.com/wsfed-sample-nomatch")

        validator = described_class.new(auth_response, @wsfed_settings)

        lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError
      end

      it 'should throw an exception when claims are empty or nil' do
        [nil, {}].each do |val|
          auth_response.stub(:attributes).and_return(val)

          validator = described_class.new(auth_response, @wsfed_settings)

          lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError
        end
      end

      it 'should throw an exception when the name_id is empty or nil' do
        [nil, ""].each do |val|
          auth_response.stub(:name_id).and_return(val)

          validator = described_class.new(auth_response, @wsfed_settings)

          lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError
        end
      end

    end

  end

end
