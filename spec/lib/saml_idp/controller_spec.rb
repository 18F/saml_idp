require 'spec_helper'
require 'saml_idp/encryptor'

describe SamlIdp::Controller do
  include SamlIdp::Controller

  def render(*); end

  def params
    @params ||= {}
  end

  def head(status, options = {}); end

  it 'finds the SAML ACS URL' do
    params[:SAMLRequest] = custom_saml_request
    validate_saml_request
    expect(saml_acs_url).to eq(saml_settings.assertion_consumer_service_url)
  end

  context 'SP-initiated logout w/o embed' do
    before do
      SamlIdp.configure do |config|
        config.service_provider.finder = lambda do |_|
          {
            certs: [
              OpenSSL::X509::Certificate.new(Base64.decode64(SamlIdp::Default::X509_CERTIFICATE)),
            ],
            private_key: SamlIdp::Default::SECRET_KEY,
            assertion_consumer_logout_service_url: 'http://foo.example.com/sp-initiated/slo',
          }
        end
      end
    end

    it 'respects Logout Request' do
      params.merge!(custom_logout_request).symbolize_keys!
      decode_request(params[:SAMLRequest])
      expect(saml_request.logout_request?).to eq true
      expect(valid_saml_request?).to eq true
    end

    it 'requires Signature be present in params' do
      params.merge!(custom_logout_request).symbolize_keys!
      params.delete(:Signature)
      decode_request(params[:SAMLRequest])

      expect(saml_request.logout_request?).to eq true
      expect(valid_saml_request?).to eq false
    end
  end

  context 'SAML Responses' do
    before do
      params[:SAMLRequest] = custom_saml_request
      validate_saml_request
    end

    let(:principal) { double email_address: 'foo@example.com' }

    it 'creates a SAML Response' do
      saml_response = encode_response(principal)
      response = OneLogin::RubySaml::Response.new(saml_response)
      name_id_format_email = Saml::XML::Namespaces::Formats::NameId::EMAIL_ADDRESS
      expect(response.name_id_format).to eq(name_id_format_email)
      expect(response.name_id).to eq('foo@example.com')
      expect(response.issuers.first).to eq('http://example.com')
      response.settings = saml_settings
      expect(response.is_valid?).to be_truthy
    end

    it 'creates a SAML Response with specified name id format' do
      name_id_format_persistent = Saml::XML::Namespaces::Formats::NameId::PERSISTENT
      opts = { name_id_format: name_id_format_persistent }
      expect(principal).to receive(:id).twice
      saml_response = encode_response(principal, opts)
      response = OneLogin::RubySaml::Response.new(saml_response)
      expect(response.name_id_format).to eq(name_id_format_persistent)
      expect(response.issuers.first).to eq('http://example.com')
    end

    it 'signs a SAML Response if requested' do
      saml_response_encoded = encode_response(principal, signed_response_message: true)
      saml_response_text = Base64.decode64(saml_response_encoded)
      saml_response = Nokogiri.XML(saml_response_text)
      response_id = saml_response.at_xpath('//*:Response').attributes['ID'].value
      signature_ref = saml_response.at_xpath('//*:Reference').attributes['URI'].value[1..-1]

      expect(signature_ref).to eq response_id
    end

    it 'creates a SAML Logout Response' do
      params[:SAMLRequest] = make_saml_logout_request
      validate_saml_request
      expect(saml_request.logout_request?).to eq true
      saml_response = encode_response(principal)
      response = OneLogin::RubySaml::Logoutresponse.new(saml_response, saml_settings)
      expect(response.validate).to eq(true)
      expect(response.issuer).to eq('http://example.com')
    end

    %i[sha1 sha256 sha384 sha512].each do |algorithm_name|
      it "creates a SAML Response using the #{algorithm_name} algorithm" do
        self.algorithm = algorithm_name
        saml_response = encode_response(principal)
        response = OneLogin::RubySaml::Response.new(saml_response)
        expect(response.name_id).to eq('foo@example.com')
        expect(response.issuers.first).to eq('http://example.com')
        response.settings = saml_settings
        expect(response.is_valid?).to be_truthy
      end

      SamlIdp::Encryptor::ENCRYPTION_ALGORITHMS_NS.keys.each do |encryption_algorithm|
        it "encrypts SAML Response assertion using #{encryption_algorithm}" do
          self.algorithm = algorithm_name
          encryption_opts = {
            cert: SamlIdp::Default::X509_CERTIFICATE,
            block_encryption: encryption_algorithm,
            key_transport: 'rsa-oaep-mgf1p',
          }

          saml_response = encode_response(principal, encryption: encryption_opts)
          resp_settings = saml_settings
          resp_settings.private_key = SamlIdp::Default::SECRET_KEY
          response = OneLogin::RubySaml::Response.new(saml_response, settings: resp_settings)
          expect(response.document.to_s).not_to match('foo@example.com')
          expect(response.decrypted_document.to_s).to match('foo@example.com')
          expect(response.name_id).to eq('foo@example.com')
          expect(response.issuers.first).to eq('http://example.com')
          expect(response.is_valid?).to be_truthy
        end
      end
    end
  end

  context 'invalid SAML Request' do
    it 'returns headers only with a forbidden status' do
      params[:SAMLRequest] = custom_saml_request(overrides: {issuer: ''})

      expect(self).to receive(:head).with(:forbidden)

      validate_saml_request
    end
  end

  context 'invalid XML in SAML Request' do
    # This was encountered IRL on 2021-02-09
    before do
      allow_any_instance_of(subject).to receive(:valid_saml_request?).and_raise(Nokogiri::XML::SyntaxError)
    end

    it 'returns headers only with a bad_request status' do
      params[:SAMLRequest] = custom_saml_request

      expect(self).to receive(:head).with(:bad_request)

      validate_saml_request
    end
  end
end
