require 'spec_helper'
module SamlIdp
  describe ServiceProvider do
    subject { described_class.new attributes }
    let(:attributes) { {} }
    let(:cert) { saml_settings.get_sp_cert }
    let(:options) { {} }

    it { is_expected.to respond_to :metadata_url }
    it { is_expected.not_to be_valid }

    describe 'with attributes' do
      let(:attributes) { { metadata_url: metadata_url } }
      let(:metadata_url) { 'http://localhost:3000/metadata' }

      it 'has a valid metadata_url' do
        expect(subject.metadata_url).to eq(metadata_url)
      end

      it { is_expected.to be_valid }
    end

    describe '#valid_signature' do
      let(:raw_xml) do
        SamlIdp::Request.from_deflated_request(
          make_saml_request
        ).raw_xml
      end

      let(:doc) {  Saml::XML::Document.parse(raw_xml) }

      describe 'the signature is not required' do
        describe 'the service provider has no certs' do
          it 'returns true' do
            expect(subject.valid_signature?(doc)).to be true
          end
        end

        describe 'the service provider has certs' do
          before { subject.certs = [cert] }
          it 'returns true' do
            expect(subject.valid_signature?(doc)).to be true
          end
        end
      end

      describe 'the signature is required' do
        before { subject.validate_signature = true }

        describe 'a cert is not present in the document' do
          let(:raise_request_errors) { nil }
          let(:raw_xml) do
            SamlIdp::Request.from_deflated_request(
              signed_auth_request_options['SAMLRequest']
            ).raw_xml
          end
          let(:options) do
            {
              get_params: signed_auth_request_options,
              raise_request_errors: raise_request_errors
            }.with_indifferent_access
          end

          describe 'the service provider has no certs' do
            it 'raises an error' do
              expect { subject.valid_signature?(doc, true, options) }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,  'No cert')
            end
          end

          describe 'the service provider has one or more certs' do
            describe 'one valid cert' do
              before { subject.certs = [cert] }

              it 'returns true' do
                expect(subject.valid_signature?(doc, true, options)).to be true
              end
            end

            describe 'one invalid cert' do
              before { subject.certs = [invalid_cert]}
              it 'raises an error' do
                expect { subject.valid_signature?(doc, true, options) }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,  'No matching cert')
              end
            end

            describe 'multiple certs' do
              before { subject.certs = [invalid_cert, cert] }

              describe "one is valid" do
                it 'returns true' do
                  expect(subject.valid_signature?(doc, true, options)).to be true
                end
              end
            end
          end
        end

        describe 'a cert is present in the document' do
          let(:raw_xml) do
            SamlIdp::Request.from_deflated_request(
              signed_auth_request
            ).raw_xml
          end

          describe 'the service provider has no certs' do
            it 'raises an error' do
              expect { subject.valid_signature?(doc, true, options) }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,  'No cert')
            end
          end

          describe 'the service provider has one or more certs' do
            describe 'one valid cert' do
              before { subject.certs = [cert] }

              it 'returns true' do
                expect(subject.valid_signature?(doc)).to be true
              end
            end

            describe 'one invalid cert' do
              before { subject.certs = [invalid_cert]}

              it 'raises an error' do
                expect { subject.valid_signature?(doc, true, options) }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,  'No matching cert')
              end
            end

            describe 'multiple certs' do
              let(:other_cert) do
                OpenSSL::X509::Certificate.new(cloudhsm_idp_x509_cert)
              end

              describe 'the valid cert is registered in the idp' do
                before { subject.certs = [other_cert, invalid_cert, cert] }

                it 'returns true' do
                  expect(subject.valid_signature?(doc, true)).to be true
                end

                it 'matches the right cert' do
                  subject.valid_signature?(doc)
                  expect(subject.matching_cert).to eq cert
                end
              end

              describe 'the valid cert is not registered in the idp' do
                before { subject.certs = [other_cert, invalid_cert] }

                it 'raises an error' do
                  expect { subject.valid_signature?(doc, true, options) }.to raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,  'No matching cert')
                end
              end
            end
          end
        end
      end
    end
  end
end
