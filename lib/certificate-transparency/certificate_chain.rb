require 'forwardable'

# A chain of certificates, from an end-entity certificate to a root certificate
# presumably trusted by the log.
#
# This is a fairly thin wrapper around an `Array`, with methods for serialization
# and deserialization.
#
class CertificateTransparency::CertificateChain
	extend Forwardable

	def_delegators :@chain, :length, :<<, :each

	include Enumerable

	# Create a {CT::CertificateChain} instance from a binary blob.
	#
	# You have to be slightly careful with this; for different types of `MerkleTreeLeaf`,
	# the serialized data that comes out of `/get-entries` is different.
	#
	# @param blob [String]
	#
	# @return [CT::CertificateChain}
	#
	def self.from_blob(blob)
		new.tap do |cc|
			chain, rest = TLS::Opaque.from_blob(blob, 2**24-1)

			unless rest.empty?
				raise ArgumentError,
				      "Malformed CertificateChain blob: " +
				      "unexpected additional data: #{rest.inspect}"
			end

			chain = chain.value
			until chain.empty?
				cert_blob, chain = TLS::Opaque.from_blob(chain, 2**24-1)

				cc << OpenSSL::X509::Certificate.new(cert_blob.value)
			end
		end
	end

	def initialize
		@chain = []
	end

	# Generate an encoded blob of this certificate chain.
	#
	# @return [String]
	#
	def to_blob
		TLS::Opaque.new(@chain.map { |c| TLS::Opaque.new(c.to_der, 2**24-1).to_blob }.join, 2**24-1).to_blob
	end
end
