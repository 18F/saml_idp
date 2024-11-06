require 'spec_helper'
require 'xml_security'

module SamlIdp
  describe 'XmlSecurity::SignedDocument' do
    let(:xml_string) { fixture('valid_SHA256.xml', path: 'requests') }
    let(:ds_namespace) { { 'ds' => 'http://www.w3.org/2000/09/xmldsig#' } }
    let(:auth_request) { custom_saml_request }
    let(:request) { Request.from_deflated_request(auth_request) }
    let(:base64_cert_text) { saml_settings.certificate }
    let(:base64_cert) { OpenSSL::X509::Certificate.new(begin_end_cert(saml_settings.certificate)) }

    subject do
      request.send(:document).signed_document
    end

    describe '#validate_doc' do
      describe 'when softly validating' do
        before do
          allow(subject).to receive(:digests_match?).and_return false
        end

        it 'does not throw NS related exceptions' do
          expect(subject.validate_doc(base64_cert_text, true)).to be_falsey
        end

        context 'with multiple validations' do
          it 'does not raise an error' do
            expect { 2.times { subject.validate_doc(base64_cert_text, true) } }.not_to raise_error
          end
        end
      end

      describe 'when throwing errors' do
        context 'when when the certs do not match' do
          let(:wrong_cert) { xml_cert_text(custom_idp_x509_cert) }

          it 'raises key validation error' do
            expect { subject.validate_doc(wrong_cert, false) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Key validation error'
              )
            )
          end
        end

        context 'when the digests do not match' do
          before do
            allow(subject).to receive(:digests_match?).and_return false
          end

          it 'raises digests error' do
            expect { subject.validate_doc(base64_cert_text, false) }.to(
              raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                          'Digest mismatch')
            )
          end
        end
      end
    end

    describe '#validate' do
      describe 'errors' do
        before do
          allow(subject.document).to receive(:at_xpath).and_call_original
        end

        context 'when certificate is invalid' do
          let(:cert_element) { double Nokogiri::XML::Element }
          let(:wrong_cert) { "not-a-certificate" }

          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(cert_element)

            allow(cert_element).to receive(:text).and_return(wrong_cert)
          end

          it 'raises invalid certificates when the document certificate is invalid' do
            expect { subject.validate('fingerprint', false) }.to(
              raise_error(SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                          'Invalid certificate')
            )
          end
        end

        context 'when x509Certicate is missing entirely' do
          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(nil)
          end

          it 'raises validation error when the X509Certificate is missing' do
            expect { subject.validate('fingerprint', false) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Certificate element missing in response (ds:X509Certificate) and not provided in options[:cert]'
              )
            )
          end
        end

        context 'when X509 element exists but is empty returns nil' do
          let(:cert_element) { double Nokogiri::XML::Element }

          before do
            allow(subject.document).to receive(:at_xpath).
              with('//ds:X509Certificate | //X509Certificate', ds_namespace).
              and_return(cert_element)

            allow(cert_element).to receive(:text).and_return('')
          end

          it 'raises a validation error when find_base64_cert_text returns nil' do
            expect { subject.validate('a fingerprint', false) }.to(
              raise_error(
                SamlIdp::XMLSecurity::SignedDocument::ValidationError,
                'Certificate element present in response (ds:X509Certificate) but evaluating to nil'
              )
            )
          end
        end
      end

      describe '#digest_method_algorithm' do
        subject { XMLSecurity::SignedDocument.new(xml_string) }

        let(:xml_string) { fixture('valid_no_ns.xml', path: 'requests') }
        let(:sig_element) do
          subject.document.at_xpath('//ds:Signature | //Signature', ds_namespace)
        end

        let(:ref) do
          sig_element.at_xpath('//ds:Reference | //Reference', ds_namespace)
        end

        context 'when document does not have ds namespace for Signature elements' do
          it 'returns the value in the DigestMethod node' do
            expect(subject.send(:digest_method_algorithm, ref)).to eq OpenSSL::Digest::SHA256
          end
        end

        context 'document does have ds namespace for Signature elements' do
          let(:xml_string) do
            SamlIdp::Request.from_deflated_request(custom_saml_request).raw_xml
          end

          it 'returns the value in the DigestMethod node' do
            expect(subject.send(:digest_method_algorithm, ref)).to eq OpenSSL::Digest::SHA256
          end
        end
      end

      describe 'Algorithms' do
        let(:signature_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha#{algorithm}" }
        let(:digest_method) { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha#{algorithm}" }

        let(:auth_request) do
          custom_saml_request(
            security_overrides: {
              signature_method:,
              digest_method:,
            }
          )
        end

        context 'when SHA1' do
          let(:signature_method) { 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha1' }
          let(:digest_method) { 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha1' }

          it 'validate using SHA1' do
            fingerprint = OpenSSL::Digest::SHA1.new(base64_cert.to_der).hexdigest
            expect(subject.validate(fingerprint)).to be_truthy
          end
        end

        context 'when SHA256' do
          let(:algorithm) { '256' }

          it 'validate using SHA256' do
            fingerprint = OpenSSL::Digest::SHA256.new(base64_cert.to_der).hexdigest
            expect(subject.validate(fingerprint)).to be_truthy
          end
        end

        context 'SHA384' do
          let(:algorithm) { '384' }

          it 'validate using SHA384' do
            fingerprint = OpenSSL::Digest::SHA384.new(base64_cert.to_der).hexdigest
            expect(subject.validate(fingerprint)).to be_truthy
          end
        end

        context 'SHA512' do
          let(:algorithm) { '512' }

          it 'validate using SHA512' do
            fingerprint = OpenSSL::Digest::SHA512.new(base64_cert.to_der).hexdigest
            expect(subject.validate(fingerprint)).to be_truthy
          end
        end
      end
    end

    describe '#extract_inclusive_namespaces' do
      context 'explicit namespace resolution' do
        it 'supports explicit namespace resolution for exclusive canonicalization' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to eq(%w[#default samlp saml ds xs xsi md])
        end
      end

      context 'implicit namespace resolution' do
        subject { XMLSecurity::SignedDocument.new(xml_string) }
        # using XML response to test no namespace for the InclusiveNamespaces element
        let(:xml_string) { fixture('no_signature_ns.xml') }

        it 'supports implicit namespace resolution for exclusive canonicalization' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to eq(%w[#default saml ds xs xsi])
        end
      end

      context 'inclusive namespace element is missing' do
        before do
          allow(subject.document).to receive(:at_xpath).
            with('//ec:InclusiveNamespaces', { 'ec' => 'http://www.w3.org/2001/10/xml-exc-c14n#' }).
            and_return(nil)
        end

        it 'return an empty list when inclusive namespace element is missing' do
          inclusive_namespaces = subject.send(:extract_inclusive_namespaces)

          expect(inclusive_namespaces).to be_empty
        end
      end
    end
  end
end
