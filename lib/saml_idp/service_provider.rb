require 'httparty'
require 'saml_idp/attributeable'
require 'saml_idp/incoming_metadata'
require 'saml_idp/persisted_metadata'
module SamlIdp
  class ServiceProvider
    include Attributeable
    attribute :identifier
    attribute :certs
    attribute :metadata_url
    attribute :validate_signature
    attribute :acs_url
    attribute :assertion_consumer_logout_service_url

    delegate :config, to: :SamlIdp

    def valid?
      attributes.present?
    end

    def valid_signature?(doc, require_signature = false, options = {})
      if require_signature || should_validate_signature?
        Array(certs).any? do |cert|
          fingerprint = fingerprint_cert(cert)
          fingerprint && doc.valid_signature?(fingerprint, options.merge(cert: cert))
        end
      else
        true
      end
    end

    # @see SamlIdp::XMLSecurity::SignedDocument#find_base64_cert
    # @param [String] string representation of an X509 cert
    def fingerprint_cert(ssl_cert)
      return nil unless ssl_cert.present?
      OpenSSL::Digest::SHA256.new(
        OpenSSL::X509::Certificate.new(Base64.decode64(ssl_cert)).to_der
      ).hexdigest
    rescue OpenSSL::X509::CertificateError
      nil
    end

    def should_validate_signature?
      attributes[:validate_signature] ||
        current_metadata.respond_to?(:sign_assertions?) && current_metadata.sign_assertions?
    end

    def refresh_metadata
      fresh = fresh_incoming_metadata
      if valid_signature?(fresh.document)
        metadata_persister[identifier, fresh]
        @current_metadata = nil
        fresh
      end
    end

    def current_metadata
      @current_metadata ||= get_current_or_build
    end

    def get_current_or_build
      persisted = metadata_getter[identifier, self]
      if persisted.is_a? Hash
        PersistedMetadata.new(persisted)
      end
    end
    private :get_current_or_build

    def metadata_getter
      config.service_provider.persisted_metadata_getter
    end
    private :metadata_getter

    def metadata_persister
      config.service_provider.metadata_persister
    end
    private :metadata_persister

    def fresh_incoming_metadata
      IncomingMetadata.new request_metadata
    end
    private :fresh_incoming_metadata

    def request_metadata
      metadata_url.present? ? HTTParty.get(metadata_url).body : ""
    end
    private :request_metadata
  end
end
