require 'addressable/uri'
require 'active_model'

module ActiveModel
  module Validations
    class UrlValidator < ActiveModel::EachValidator

      def initialize(options)
        options.reverse_merge!(schemes: %w(http https))
        options.reverse_merge!(message: "is not a valid URL")
        options.reverse_merge!(reachable: false)
        super(options)
      end

      def validate_each(record, attribute, value)
        schemes = [*options.fetch(:schemes)].map(&:to_s)
        begin
          uri = Addressable::URI.parse(value)
          unless uri && schemes.include?(uri.scheme)
            record.errors.add(attribute, "'s scheme is not one of #{schemes.join(' or ')}", value: value)
          end
          if options[:reachable] and %w(http https).include?(uri.scheme)
            begin
              case Net::HTTP.get_response(uri)
                when Net::HTTPSuccess then true
                when Net::HTTPRedirection then true
                else record.errors.add(attribute, 'is a valid URL, but could not be accessed.', value: value) and false
              end
            rescue Exception => e
              record.errors.add(attribute, "is a valid URL, but DNS lookup failed. Reason: #{e.try(:message)} ", value: value) and false
            end
          end
        rescue Addressable::URI::InvalidURIError
          record.errors.add(attribute, options.fetch(:message), value: value)
        end
      end
    end

    module ClassMethods
      # Validates whether the value of the specified attribute is valid url.
      #
      #   class Unicorn
      #     include ActiveModel::Validations
      #     attr_accessor :homepage, :ftpsite
      #     validates_url :homepage, :allow_blank => true
      #     validates_url :ftpsite, :schemes => ['ftp']
      #   end
      # Configuration options:
      # * <tt>:message</tt> - A custom error message (default is: "is not a valid URL").
      # * <tt>:allow_nil</tt> - If set to true, skips this validation if the attribute is +nil+ (default is +false+).
      # * <tt>:allow_blank</tt> - If set to true, skips this validation if the attribute is blank (default is +false+).
      # * <tt>:schemes</tt> - Array of URI schemes to validate against. (default is +['http', 'https']+)

      def validates_url(*attr_names)
        validates_with UrlValidator, _merge_attributes(attr_names)
      end
    end
  end
end


# Thanks Ilya! http://www.igvita.com/2006/09/07/validating-url-in-ruby-on-rails/
# Original credits: http://blog.inquirylabs.com/2006/04/13/simple-uri-validation/
# HTTP Codes: http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/classes/Net/HTTPResponse.html
