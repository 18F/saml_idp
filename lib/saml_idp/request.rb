require 'saml_idp/xml_security'
require 'saml_idp/service_provider'
module SamlIdp
  class Request
    VTR_REGEXP = /\A[A-Z][a-z0-9](\.[A-Z][a-z0-9])*\z/

    def self.from_deflated_request(raw, options = {})
      if raw
        log "#{'~' * 20} RAW Request #{'~' * 20}\n#{raw}\n#{'~' * 18} Done RAW Request #{'~' * 17}\n"
        decoded = Base64.decode64(raw.gsub('\\r', '').gsub('\\n', ''))
        zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        begin
          inflated = zstream.inflate(decoded).tap do
            zstream.finish
            zstream.close
          end
        rescue Zlib::BufError, Zlib::DataError # not compressed
          inflated = decoded
        end
      else
        inflated = ''
      end
      new(inflated, options)
    end

    def self.log(msg, level: :debug)
      if Rails&.logger
        Rails.logger.send(level, msg)
      else
        puts msg
      end
    end

    attr_accessor :raw_xml, :options
    attr_reader :errors

    delegate :config, to: :SamlIdp
    private :config
    delegate :xpath, to: :document
    private :xpath

    def initialize(raw_xml = '', options = {})
      self.options = options
      self.raw_xml = raw_xml
      @errors = []
    end

    def logout_request?
      logout_request.nil? ? false : true
    end

    def authn_request?
      authn_request.nil? ? false : true
    end

    def request_id
      request['ID']
    end

    def request
      if authn_request?
        authn_request
      elsif logout_request?
        logout_request
      end
    end

    def force_authn?
      return nil unless authn_request?

      request['ForceAuthn'] == 'true'
    end

    def requested_authn_context_comparison
      requested_authn_context_node['Comparison'] if authn_request? && requested_authn_context_node
    end

    def requested_authn_contexts
      if authn_request? && !authn_context_nodes.empty?
        authn_context_nodes.map(&:content)
      else
        []
      end
    end

    def requested_vtr_authn_contexts
      requested_authn_contexts.select do |classref|
        VTR_REGEXP.match?(classref)
      end
    end

    def acs_url
      service_provider.acs_url ||
        authn_request['AssertionConsumerServiceURL'].to_s
    end

    def logout_url
      service_provider.assertion_consumer_logout_service_url
    end

    def response_url
      if authn_request?
        acs_url
      elsif logout_request?
        logout_url
      end
    end

    def log(msg)
      if Rails&.logger
        Rails.logger.info msg
      else
        puts msg
      end
    end

    def valid?
      log 'Checking validity...'

      unless service_provider?
        log "Unable to find service provider for issuer #{issuer}"
        errors.push(:issuer_missing_or_invald)
      end

      if authn_request? && logout_request?
        log 'One and only one of authnrequest and logout request is required.'
        errors.push(:both_auth_and_logout_request)
      end

      unless authn_request? || logout_request?
        log "One and only one of authnrequest and logout request is required. authnrequest: #{authn_request?} logout_request: #{logout_request?} "
        errors.push(:no_auth_or_logout_request)
      end

      if service_provider? && response_url.blank?
        log "Unable to find response url for #{issuer}: #{raw_xml}"
        errors.push(:no_response_url)
      end

      unless service_provider? && valid_signature?
        log "Signature is invalid in #{raw_xml}"
        # TODO: We should get more specific errors
        errors.push(:invalid_signature)
      end

      errors.blank?
    end

    def matching_cert
      return nil unless signed?

      Array(service_provider.certs).find do |cert|
        document.valid_signature?(cert, options)
      end
    end

    def cert_errors
      return nil unless signed?

      begin
        return nil if matching_cert.present?
      rescue SamlIdp::XMLSecurity::SignedDocument::ValidationError => e
        return [{ cert: nil, error_code: e.error_code }]
      end

      return [{ cert: nil, error_code: :no_registered_certs }] if service_provider.certs.blank?

      Array(service_provider.certs).map do |cert|
        document.gather_errors(cert, options)
      end
    end

    def signed?
      document.signed? || !!options[:get_params]&.key?(:Signature)
    end

    def valid_signature?
      # Force signatures for logout requests because there is no other
      # protection against a cross-site DoS.
      service_provider.valid_signature?(
        matching_cert,
        logout_request?
      )
    end

    def service_provider?
      service_provider&.valid?
    end

    def service_provider
      return if issuer.blank?

      @_service_provider ||= ServiceProvider.new((service_provider_finder[issuer] || {}).merge(identifier: issuer))
    end

    def issuer
      @_issuer ||= xpath('//saml:Issuer', saml: assertion).first.try(:content)
      @_issuer.presence
    end

    def name_id
      @_name_id ||= xpath('//saml:NameID', saml: assertion).first.try(:content)
    end

    def name_id_format
      return name_id_format_node.content if authn_request? && name_id_format_node

      nil
    end

    def session_index
      @_session_index ||= xpath('//samlp:SessionIndex', samlp:).first.try(:content)
    end

    def document
      @_document ||= Saml::XML::Document.parse(raw_xml)
    end
    private :document

    def name_id_format_node
      return @_name_id_format_node if defined?(@_name_id_format_node)

      @_name_id_format_node ||= xpath('//samlp:AuthnRequest/samlp:NameIDPolicy/@Format',
                                      samlp:,
                                      saml: assertion).first
    end
    private :name_id_format_node

    def requested_authn_context_node
      @_authn_context_node ||= xpath('//samlp:AuthnRequest/samlp:RequestedAuthnContext',
                                     samlp:,
                                     saml: assertion).first
    end
    private :requested_authn_context_node

    def authn_context_node
      @_authn_context_node ||= xpath('//samlp:AuthnRequest/samlp:RequestedAuthnContext/saml:AuthnContextClassRef',
                                     samlp:,
                                     saml: assertion).first
    end
    private :authn_context_node

    def authn_context_nodes
      @_authn_context_nodes ||= xpath('//samlp:AuthnRequest/samlp:RequestedAuthnContext/saml:AuthnContextClassRef',
                                      samlp:,
                                      saml: assertion)
    end
    private :authn_context_nodes

    def authn_request
      @_authn_request ||= xpath('//samlp:AuthnRequest', samlp:).first
    end
    private :authn_request

    def logout_request
      @_logout_request ||= xpath('//samlp:LogoutRequest', samlp:).first
    end
    private :logout_request

    def samlp
      Saml::XML::Namespaces::PROTOCOL
    end
    private :samlp

    def assertion
      Saml::XML::Namespaces::ASSERTION
    end
    private :assertion

    def signature_namespace
      Saml::XML::Namespaces::SIGNATURE
    end
    private :signature_namespace

    def service_provider_finder
      config.service_provider.finder
    end
    private :service_provider_finder
  end
end
