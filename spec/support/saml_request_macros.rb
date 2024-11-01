require 'saml_idp/logout_request_builder'

module SamlRequestMacros
  def make_saml_request(requested_saml_acs_url = 'https://foo.example.com/saml/consume')
    auth_url = url(saml_settings(requested_saml_acs_url))
    CGI.unescape(auth_url.split('=').last)
  end

  def custom_saml_request(overrides: {}, security_overrides: {}, signed: true)
    auth_url = url(
      custom_saml_settings(
        overrides:,
        security_overrides:,
        signed:
      )
    )

    CGI.unescape(auth_url.split('=').last)
  end

  def url(saml_settings)
    auth_request = OneLogin::RubySaml::Authrequest.new
    auth_request.create(saml_settings)
  end

  def signed_auth_request
    CGI.unescape(url(signed_saml_settings).split('=').last)
  end

  def signed_auth_request_options
    signed_auth_request_options ||=
      uri = URI(url(signed_saml_settings(embed: false)))
    Rack::Utils.parse_nested_query uri.query
  end

  def make_saml_logout_request(requested_saml_logout_url = 'https://foo.example.com/saml/logout')
    request_builder = SamlIdp::LogoutRequestBuilder.new(
      'some_response_id',
      'http://example.com',
      requested_saml_logout_url,
      'some_name_id',
      OpenSSL::Digest::SHA256
    )
    request_builder.encoded
  end

  def make_sp_logout_request(requested_saml_logout_url = 'https://foo.example.com/saml/logout')
    settings = saml_settings.dup
    settings.assertion_consumer_logout_service_url = requested_saml_logout_url
    settings.name_identifier_value = 'some-user-id'
    OneLogin::RubySaml::Logoutrequest.new.create(settings)
  end

  def custom_logout_request(overrides: {})
    settings = saml_settings.dup
    settings.assertion_consumer_logout_service_url = 'https://foo.example.com/saml/logout'
    settings.name_identifier_value = 'some-user-id'

    settings.security = {
      embed_sign: false,
      logout_requests_signed: true,
      want_assertions_signed: true,
      digest_method: 'http://www.w3.org/2001/04/xmlenc#sha256',
      signature_method: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    }

    security_overrides.each do |key|
      settings.security.send(:"#{key}=", security_overrides[key])
    end

    overrides.keys.each do |key|
      settings.send(:"#{key}=", overrides[key])
    end

    uri = URI(OneLogin::RubySaml::Logoutrequest.new.create(settings))
    Rack::Utils.parse_nested_query uri.query
  end

  def saml_settings(requested_saml_acs_url = 'https://foo.example.com/saml/consume')
    settings = OneLogin::RubySaml::Settings.new
    settings.assertion_consumer_service_url = requested_saml_acs_url
    settings.issuer = 'http://example.com/issuer'
    settings.idp_sso_target_url = 'http://idp.com/saml/idp'
    settings.idp_slo_target_url = 'http://idp.com/saml/idp-slo'
    settings.idp_cert_fingerprint = SamlIdp::Default::FINGERPRINT
    settings.name_identifier_format = SamlIdp::Default::NAME_ID_FORMAT
    settings.certificate = SamlIdp::Default::X509_CERTIFICATE
    settings.private_key = SamlIdp::Default::SECRET_KEY
    settings.security = {
      embed_sign: false,
      logout_requests_signed: true,
      digest_method: 'http://www.w3.org/2001/04/xmlenc#sha256',
      signature_method: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    }
    settings
  end

  def signed_saml_settings(embed: true)
    settings = saml_settings('https://foo.example.com/saml/consume').dup

    settings.security = {
      embed_sign: embed,
      authn_requests_signed: true,
      want_assertions_signed: true,
      digest_method: 'http://www.w3.org/2001/04/xmlenc#sha256',
      signature_method: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    }
    settings
  end

  def custom_saml_settings(overrides:, security_overrides:, signed:)
    settings = saml_settings.dup

    overrides.keys.each do |key|
      settings.send("#{key}=".to_sym, overrides[key])
    end

    if signed
      # set security options, then override any that need it
      settings.security = {
        embed_sign: true,
        authn_requests_signed: true,
        want_assertions_signed: true,
        digest_method: 'http://www.w3.org/2001/04/xmlenc#sha256',
        signature_method: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      }
      security_overrides.each do |key|
        settings.security.send("#{key}=".to_sym, security_overrides[key])
      end
    end

    settings
  end
end
