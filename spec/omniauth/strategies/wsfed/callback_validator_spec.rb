require 'spec_helper'

describe OmniAuth::Strategies::WSFed::CallbackValidator do

  describe 'Response Validation Rules' do

    let(:auth_callback) { OmniAuth::Strategies::WSFed::AuthCallback.new({}, {})}

    before(:each) do
      @wsfed_settings = {
          :issuer_name  => "https://identity-wwf.accesscontrol.windows.net/",
          :realm        => "http://rp.wwf.com/wsfed-sample",
          :id_claim     => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
      }

      @claims = {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"                => "ravishing_rick@wwf.com",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"                        => "rick.rude",
        "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider" => "http://sso.wwf.com"
      }

      auth_callback.stub(:issuer).and_return(@wsfed_settings[:issuer_name])
      auth_callback.stub(:audience).and_return(@wsfed_settings[:realm])
      auth_callback.stub(:claims).and_return(@claims)
      auth_callback.stub(:name_id).and_return(@claims[@wsfed_settings[:id_claim]])
      auth_callback.stub(:created_at).and_return(Time.now.utc - 1) # 1 second ago
      auth_callback.stub(:expires_at).and_return(Time.now.utc + 300) # 5 minutes from now
    end

    it 'should pass validation with....' do
      validator = described_class.new(auth_callback, @wsfed_settings)

      validator.validate!.should == true
    end

    context 'with Invalid Response' do

      it 'should throw an exception when issuers do not match' do
        auth_callback.stub(:issuer).and_return("https://c4sc-federation-nomatch.accesscontrol.windows.net/")

        validator = described_class.new(auth_callback, @wsfed_settings)

        lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                          OmniAuth::Strategies::WSFed::CallbackValidator::ISSUER_MISMATCH
      end

      it 'should throw an exception when realm/audience do not match' do
        auth_callback.stub(:audience).and_return("http://rp.c4sc.com/wsfed-sample-nomatch")

        validator = described_class.new(auth_callback, @wsfed_settings)

        lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                          OmniAuth::Strategies::WSFed::CallbackValidator::AUDIENCE_MISMATCH
      end

      it 'should throw an exception when the created_at timestamp is in the future' do
        auth_callback.stub(:created_at).and_return(Time.now.utc + 2)

        validator = described_class.new(auth_callback, @wsfed_settings)

        lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                          OmniAuth::Strategies::WSFed::CallbackValidator::FUTURE_CREATED_AT
      end

      it 'should throw an exception when the expires_at timestamp limit has been exceeded' do
        auth_callback.stub(:expires_at).and_return(Time.now.utc - 1)

        validator = described_class.new(auth_callback, @wsfed_settings)

        lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                          OmniAuth::Strategies::WSFed::CallbackValidator::TOKEN_EXPIRED
      end

      it 'should throw an exception when claims are empty or nil' do
        [nil, {}].each do |val|
          auth_callback.stub(:claims).and_return(val)

          validator = described_class.new(auth_callback, @wsfed_settings)

          lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                            OmniAuth::Strategies::WSFed::CallbackValidator::NO_CLAIMS
        end
      end

      it 'should throw an exception when the name_id is empty or nil' do
        [nil, ""].each do |val|
          auth_callback.stub(:name_id).and_return(val)

          validator = described_class.new(auth_callback, @wsfed_settings)

          lambda { validator.validate! }.should raise_error OmniAuth::Strategies::WSFed::ValidationError,
                                                            OmniAuth::Strategies::WSFed::CallbackValidator::NO_USER_IDENTIFIER
        end
      end

    end

  end

end
