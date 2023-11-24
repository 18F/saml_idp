require 'spec_helper'
module SamlIdp
  describe Request do
    let(:aal) { 'http://idmanagement.gov/ns/assurance/aal/3' }
    let(:default_aal) { 'urn:gov:gsa:ac:classes:sp:PasswordProtectedTransport:duo' }
    let(:ial) { 'http://idmanagement.gov/ns/assurance/ial/2' }
    let(:vtr) { 'C1.C2.P1.Pb' }
    let(:password) { 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password' }
    let(:authn_context_classref) { build_authn_context_classref(password) }
    let(:issuer) { 'localhost:3000' }
    let(:raw_authn_request) do
      "<samlp:AuthnRequest AssertionConsumerServiceURL='http://localhost:3000/saml/consume' Destination='http://localhost:1337/saml/auth' ID='_af43d1a0-e111-0130-661a-3c0754403fdb' IssueInstant='2013-08-06T22:01:35Z' Version='2.0' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate='true' Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'/><samlp:RequestedAuthnContext Comparison='exact'>#{authn_context_classref}</samlp:RequestedAuthnContext></samlp:AuthnRequest>"
    end

    let(:raw_authn_unspecified_name_id_format) do
      "<samlp:AuthnRequest AssertionConsumerServiceURL='http://localhost:3000/saml/consume' Destination='http://localhost:1337/saml/auth' ID='_af43d1a0-e111-0130-661a-3c0754403fdb' IssueInstant='2013-08-06T22:01:35Z' Version='2.0' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{issuer}</saml:Issuer><samlp:RequestedAuthnContext Comparison='exact'><saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"
    end

    let(:raw_authn_forceauthn_present) do
      "<samlp:AuthnRequest AssertionConsumerServiceURL='http://localhost:3000/saml/consume' Destination='http://localhost:1337/saml/auth' ID='_af43d1a0-e111-0130-661a-3c0754403fdb' IssueInstant='2013-08-06T22:01:35Z' Version='2.0' ForceAuthn='true' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{issuer}</saml:Issuer><samlp:RequestedAuthnContext Comparison='exact'><saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"
    end

    let(:raw_authn_forceauthn_false) do
      "<samlp:AuthnRequest AssertionConsumerServiceURL='http://localhost:3000/saml/consume' Destination='http://localhost:1337/saml/auth' ID='_af43d1a0-e111-0130-661a-3c0754403fdb' IssueInstant='2013-08-06T22:01:35Z' Version='2.0' ForceAuthn='false' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{issuer}</saml:Issuer><samlp:RequestedAuthnContext Comparison='exact'><saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"
    end

    let(:raw_authn_enveloped_signature) do
      "<samlp:AuthnRequest AssertionConsumerServiceURL='http://localhost:3000/saml/consume' Destination='http://localhost:1337/saml/auth' ID='_af43d1a0-e111-0130-661a-3c0754403fdb' IssueInstant='2013-08-06T22:01:35Z' Version='2.0' ForceAuthn='false' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>localhost:3000</saml:Issuer><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'></ds:Signature><samlp:RequestedAuthnContext Comparison='exact'><saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"
    end

    let(:raw_logout_request) do
      "<LogoutRequest ID='_some_response_id' Version='2.0' IssueInstant='2010-06-01T13:00:00Z' Destination='http://localhost:3000/saml/logout' xmlns='urn:oasis:names:tc:SAML:2.0:protocol'><Issuer xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>http://example.com</Issuer><NameID xmlns='urn:oasis:names:tc:SAML:2.0:assertion' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'>some_name_id</NameID><SessionIndex>abc123index</SessionIndex></LogoutRequest>"
    end

    let(:options) { {} }
    let(:deflated_request) { make_saml_request }
    subject { described_class.from_deflated_request deflated_request, options }

    describe 'deflated request' do
      it 'inflates' do
        expect(subject.issuer).to eq(saml_settings.issuer)
      end

      describe 'invalid SAML' do
        let(:deflated_request) { 'bang!' }
        it 'does not set attributes' do
          expect(subject.issuer).to be nil
        end
      end

      describe 'no request passed in' do
        let(:deflated_request) { nil }

        it 'sets raw_xml to an empty string' do
          expect(subject.raw_xml).to eq ''
        end
      end

      it 'returns acs_url for response_url' do
        expect(subject.response_url).to eq(subject.acs_url)
      end

      it 'is a authn request' do
        expect(subject.authn_request?).to eq(true)
      end

      it 'fetches internal request' do
        expect(subject.request['ID']).to eq(subject.request_id)
      end

      it 'has a valid name id format' do
        expect(subject.name_id_format).to eq('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
      end

      it 'has a valid requested authn context comparison' do
        expect(subject.requested_authn_context_comparison).to eq('exact')
      end

      it 'has a valid authn context' do
        expect(subject.requested_authn_context).to eq('urn:oasis:names:tc:SAML:2.0:ac:classes:Password')
      end

      context 'empty issuer' do
        let(:issuer) { nil }

        it 'does not permit empty issuer' do
          expect(subject.issuer).not_to eq('')
          expect(subject.issuer).to eq(nil)
        end

        it 'has a valid service_provider' do
          expect(subject.service_provider).to be_a ServiceProvider
        end

        it 'has a valid service_provider' do
          expect(subject.service_provider.valid?).to be true
        end

        it 'has a valid issuer' do
          expect(subject.issuer).to eq(saml_settings.issuer)
        end

        it 'has a valid valid_signature' do
          expect(subject.valid_signature?).to be true
        end

        it 'correctly indicates that it is not signed' do
          expect(subject.signed?).to be false
        end

        context 'with signature in params' do
          let(:deflated_request) { signed_auth_request(embed: false) }
          let(:options) do
            { get_params: signed_auth_request_options.with_indifferent_access }
          end

          it 'correctly indicates that it is signed (even invalidly)' do
            expect(subject.signed?).to be true
          end
        end

        context 'with an enveloped signature' do
          let(:deflated_request) { signed_auth_request(embed: true) }

          it 'correctly indicates that it is signed (even invalidly)' do
            expect(subject.signed?).to be true
          end
        end

        it 'should return acs_url for response_url' do
          expect(subject.response_url).to eq(subject.acs_url)
        end

        it 'is a authn request' do
          expect(subject.authn_request?).to eq(true)
        end

        it 'fetches internal request' do
          expect(subject.request['ID']).to eq(subject.request_id)
        end

        it 'has a valid name id format' do
          expect(subject.name_id_format).to eq(saml_settings.name_identifier_format)
        end

        it 'has a valid requested authn context comparison' do
          expect(subject.requested_authn_context_comparison).to eq(saml_settings.authn_context_comparison)
        end

        it 'has a valid authn context' do
          expect(subject.requested_authn_context).to eq(saml_settings.authn_context)
        end

        context 'empty issuer' do
          let(:deflated_request) { make_invalid_saml_request}

          it 'does not permit empty issuer' do
            expect(subject.issuer).not_to eq('')
            expect(subject.issuer).to eq(nil)
          end
        end

        describe 'force_authn?' do
          describe 'it is not set' do
            it 'defaults to false' do
              expect(subject.force_authn?).to be false
            end
          end

          describe 'ForceAuthn is set' do
            let(:force_authn) { true }
            let(:deflated_request) { make_saml_request_with_options({force_authn: force_authn}) }

            it 'returns true' do
              expect(subject.force_authn?).to be true
            end

            describe 'it is set to false' do
              let(:force_authn) { false }

              it 'returns false' do
                expect(subject.force_authn?).to be false
              end
            end
          end
        end

        describe 'unspecified name id format' do
          let(:deflated_request) { make_saml_request_with_options({name_identifier_format: nil}) }

          it 'returns nil for name id format' do
            expect(subject.name_id_format).to eq(nil)
          end
        end
      end
    end

    describe 'logout request' do
      let(:deflated_request) { make_saml_logout_request }

      subject { described_class.from_deflated_request deflated_request }

      it 'has a valid request_id' do
        expect(subject.request_id).to eq('_some_response_id')
      end

      it 'is flagged as a logout_request' do
        expect(subject.logout_request?).to eq(true)
      end

      it 'has a valid name_id' do
        expect(subject.name_id).to eq('some_name_id')
      end

      it 'has a session index' do
        expect(subject.session_index).to eq('abc123index')
      end

      it 'has a valid issuer' do
        expect(subject.issuer).to eq('http://example.com')
      end

      it 'fetches internal request' do
        expect(subject.request['ID']).to eq(subject.request_id)
      end

      it 'returns logout_url for response_url' do
        expect(subject.response_url).to eq(subject.logout_url)
      end
    end

    describe '#requested_aal_authn_context' do
      let(:authn_context_classref) { '' }
      let(:deflated_request) { make_saml_request_with_options({authn_context: authn_context_classref}) }
      subject { described_class.from_deflated_request deflated_request }

      context 'no aal context requested' do
        let(:authn_context_classref) { '' }

        it 'returns nil' do
          expect(subject.requested_aal_authn_context).to be_nil
        end
      end

      context 'context requested is default aal' do
        let(:authn_context_classref) { default_aal }

        it 'returns the aal uri' do
          expect(subject.requested_aal_authn_context).to eq(default_aal)
        end
      end

      context 'only context requested is aal' do
        let(:authn_context_classref) { aal }

        it 'returns the aal uri' do
          expect(subject.requested_aal_authn_context).to eq(aal)
        end
      end

      context 'multiple contexts requested including aal' do
        let(:authn_context_classref) { [ial, aal] }

        it 'returns the aal uri' do
          expect(subject.requested_aal_authn_context).to eq(aal)
        end
      end
    end

    describe '#requested_ial_authn_context' do
      let(:authn_context_classref) { '' }
      let(:deflated_request) { make_saml_request_with_options({authn_context: authn_context_classref}) }
      subject { described_class.from_deflated_request deflated_request }

      context 'no ial context requested' do
        let(:authn_context_classref) { '' }

        it 'returns nil' do
          expect(subject.requested_ial_authn_context).to be_nil
        end
      end

      context 'only context requested is ial' do
        let(:authn_context_classref) { ial }

        it 'returns the ial uri' do
          expect(subject.requested_ial_authn_context).to eq(ial)
        end
      end

      context 'multiple contexts requested including ial' do
        let(:authn_context_classref) { [aal, ial] }

        it 'returns the ial uri' do
          expect(subject.requested_ial_authn_context).to eq(ial)
        end
      end
    end

    describe '#requested_vtr_authn_contexts' do
      subject { described_class.new raw_authn_request }

      context 'no vtr context requested' do
        let(:authn_context_classref) { '' }

        it 'returns an empty array' do
          expect(subject.requested_vtr_authn_contexts).to eq([])
        end
      end

      context 'only vtr is requested' do
        let(:authn_context_classref) { build_authn_context_classref(vtr) }

        it 'returns the vrt' do
          expect(subject.requested_vtr_authn_contexts).to eq([vtr])
        end
      end

      context 'multiple contexts including vtr and an old ACR context' do
        let(:authn_context_classref) { build_authn_context_classref([vtr, ial]) }

        it 'returns the vrt' do
          expect(subject.requested_vtr_authn_contexts).to eq([vtr])
        end
      end

      context 'multiple contexts that are vectors of trust' do
        let(:authn_context_classref) { build_authn_context_classref(['C1.C2.P1.Pb', 'C1.C2.P1']) }

        it 'returns all of the vectors in an array' do
          expect(subject.requested_vtr_authn_contexts).to eq(['C1.C2.P1.Pb', 'C1.C2.P1'])
        end
      end

      context 'context that contains a VTR substring but is not a VTR' do
        let(:authn_context_classref) do
          fake_vtr = 'Not a VTR but does contain LetT3.Rs and Nu.Mb.Ers'
          build_authn_context_classref(fake_vtr)
        end

        it 'does not match on the context' do
          expect(subject.requested_vtr_authn_contexts).to eq([])
        end
      end

      context 'with the default MFA context' do
        let(:aal) { 'urn:gov:gsa:ac:classes:sp:PasswordProtectedTransport:duo' }
        let(:authn_context_classref) { build_authn_context_classref(aal) }

        it 'does not match on the context' do
          expect(subject.requested_vtr_authn_contexts).to eq([])
        end
      end
    end

    describe '#valid?' do
      let(:request_saml) { raw_authn_request }

      subject { described_class.new request_saml }

      context 'a valid request' do
        it 'returns true' do
          expect(subject.valid?).to be true
        end

        it 'has no errors' do
          expect(subject.errors.blank?).to be true
        end
      end

      context 'an invalid request' do
        describe 'a request with no issuer' do
          let(:request_saml) { make_invalid_saml_request }

          it 'is not valid' do
            expect(subject.valid?).to eq(false)
          end

          it 'adds an error to the request object' do
            subject.valid?
            expect(subject.errors.first).to eq :issuer_missing_or_invald
          end
        end

        describe 'no authn_request OR logout_request tag' do
          let(:request_saml) do
            "<saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>localhost:3000</saml:Issuer><samlp:NameIDPolicy AllowCreate='true' Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'/><samlp:RequestedAuthnContext Comparison='exact'>http://idmanagement.gov/ns/assurance/aal/3</samlp:RequestedAuthnContext>"
          end
          subject { described_class.new(request_saml, options) }

          it 'is not valid' do
            expect(subject.valid?).to eq false
          end

          it 'adds an error to request object' do
            subject.valid?
            expect(subject.errors.first).to eq :no_auth_or_logout_request
          end
        end

        describe 'both an authn_request AND logout_request tag' do
          let(:request_saml) { make_saml_request }
          let(:logout_saml) { "<LogoutRequest ID='_some_response_id' Version='2.0' IssueInstant='2010-06-01T13:00:00Z' Destination='http://localhost:3000/saml/logout' xmlns='urn:oasis:names:tc:SAML:2.0:protocol'>" }

          before do
            subject.raw_xml = logout_saml + subject.raw_xml + '</LogoutRequest>'
          end

          it 'is not valid' do
            expect(subject.valid?).to eq false
          end

          it 'adds an error to request object' do
            subject.valid?
            expect(subject.errors.first).to eq :both_auth_and_logout_request
          end
        end

        describe 'there is no response url' do
          describe 'authn_request' do
            let(:request_saml) { make_saml_request_with_options({assertion_consumer_service_url: ''}) }

            it 'is not valid' do
              expect(subject.valid?).to eq false
            end

            it 'adds an error to request object' do
              subject.valid?
              expect(subject.errors.first).to eq :no_response_url
            end
          end

          describe 'logout_request' do
            let(:request_saml) { make_saml_logout_request }
            before do
              subject.service_provider.assertion_consumer_logout_service_url = nil
            end

            it 'is not valid' do
              expect(subject.valid?).to eq false
            end

            it 'adds an error to request object' do
              subject.valid?
              expect(subject.errors.first).to eq :no_response_url
            end
          end
        end

        describe 'invalid signature' do
          let(:options) { { get_params: signed_auth_request_options.with_indifferent_access } }
          let(:cert) { saml_settings.certificate }
          let(:registered_cert) do
            OpenSSL::X509::Certificate.new(
              "-----BEGIN CERTIFICATE-----\n" +
              cert  +
              "\n-----END CERTIFICATE-----"
            )
          end
          let(:expected_cert) { Base64.encode64(registered_cert.to_pem) }

          let(:request_saml) { signed_auth_request_options['SAMLRequest'] }

          before do
            # force signature validation
            subject.service_provider.validate_signature = true
            subject.service_provider.certs = [registered_cert]
          end

          describe 'specific errors' do
            describe 'invalid certificate' do
              before do
                expect(Base64).to receive(:decode64).with(expected_cert) { 'invalid certificate' }
              end

              it 'is not valid' do
                expect(subject.valid?).to eq false
              end

              it 'adds an error to request object' do
                subject.valid?
                expect(subject.errors.include?(:invalid_certificate)).to be true
              end
            end

            describe 'none of the service provider certs match the signed document' do
              let(:registered_cert) { OpenSSL::X509::Certificate.new(cloudhsm_idp_x509_cert) }
              it 'is not valid' do
                expect(subject.valid?).to eq false
              end

              it 'adds a key validation error to request object' do
                subject.valid?
                expect(subject.errors.include?(:key_validation_error)).to be true
              end
            end

            describe 'service provider has no certificate registered' do
              before { subject.service_provider.certs = [] }

              it 'is not valid' do
                expect(subject.valid?).to eq false
              end

              it 'adds a no_cert_registered error to request object' do
                subject.valid?
                expect(subject.errors.include?(:no_cert_registered)).to be true
              end
            end

            describe 'fingerprint mismatch' do
              before do
                allow(subject.service_provider).to receive(:valid_signature?).and_raise(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,  'Fingerprint mismatch'
                )
              end

              it 'is not valid' do
                expect(subject.valid?).to eq false
              end

              it 'adds a fingerprint mismatch error' do
                subject.valid?
                expect(subject.errors.include?(:fingerprint_mismatch)).to be true
              end
            end

            describe 'present but nil cert tag in request' do
              # TODO: This could happen if a cert tag was present in the request document
              # and the service_provider had a cert registered. should we
              # refactor the code to ignore the certificate in the request document?
              before do
                allow(subject.service_provider).to receive(:valid_signature?).and_raise(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                  'Certificate element present in response (ds:X509Certificate) but evaluating to nil'
                )
              end

              it 'is not valid' do
                expect(subject.valid?).to eq false
              end

              it 'adds a present_but_nil_cert error' do
                subject.valid?
                expect(subject.errors.include?(:present_but_nil)).to be true
              end
            end

            describe 'cert is not a cert' do
              # TODO: Not sure if this is possible based on our setup.
              before do
                allow(subject.service_provider).to receive(:valid_signature?).and_raise(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                  'options[:cert] must be Base64-encoded String or OpenSSL::X509::Certificate'
                )
              end

              it 'is not valid' do
                expect(subject.valid?).to eq false
              end

              it 'adds a not_base64_or_cert error' do
                subject.valid?
                expect(subject.errors.include?(:not_base64_or_cert)).to be true
              end
            end

            describe 'digest mismatch' do
              before do
                allow(subject.service_provider).to receive(:valid_signature?).and_raise(
                  SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                  'Digest mismatch'
                )
              end

              it 'is not valid' do
                expect(subject.valid?).to eq false
              end

              it 'adds a digest mismatch error' do
                subject.valid?
                expect(subject.errors.include?(:digest_mismatch)).to be true
              end
            end
          end
        end
      end
    end

    describe '#matching_cert' do
      let(:saml_request) { make_saml_request }

      subject do
        described_class.from_deflated_request saml_request
      end

      describe 'document is not signed' do
        it 'returns nil' do
          expect(subject.matching_cert).to be_nil
        end
      end

      describe 'document is signed' do
        let(:saml_request) { signed_auth_request }
        let(:service_provider) { subject.service_provider }
        let(:cert) { saml_settings.get_sp_cert }

        describe 'the service provider has no registered certs' do
          before { subject.service_provider.certs = [] }

          it 'returns nil' do
            expect(subject.matching_cert).to be_nil
          end
        end

        describe 'the service provider has one registered cert' do
          before { subject.service_provider.certs = [cert] }

          describe 'the cert matches the assertion cert' do
            it 'returns the cert' do
              expect(subject.matching_cert).to eq cert
            end
          end

          describe 'the cert does not match the assertion cert' do
            let(:cert) { OpenSSL::X509::Certificate.new(cloudhsm_idp_x509_cert) }

            it 'returns nil' do
              expect(subject.matching_cert).to be_nil
            end
          end
        end

        describe 'multiple certs' do
          let(:not_matching_cert) { OpenSSL::X509::Certificate.new(cloudhsm_idp_x509_cert) }

          before { subject.service_provider.certs = [not_matching_cert, invalid_cert, cert] }

          it 'returns the matching cert' do
            expect(subject.matching_cert).to eq cert
          end
        end
      end
    end

    def build_authn_context_classref(contexts)
      [contexts].flatten.map do |c|
        "<saml:AuthnContextClassRef xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>#{c}</saml:AuthnContextClassRef>"
      end.join
    end
  end
end
