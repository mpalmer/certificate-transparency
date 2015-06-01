# An RFC6962 `PreCert` structure.
#
class CertificateTransparency::PreCert
	attr_accessor :issuer_key_hash, :tbs_certificate

	# Parse a binary blob into a PreCert structure.
	#
	# It is uncommon to call this directly.  Because of the way that the
	# PreCert is encoded, you have to parse the component parts out of the
	# `TimestampedEntry`; however, this method is here if you need it.
	#
	# @param blob [String]
	#
	# @return [CertificateTransparency::PreCert]
	#
	def self.from_blob(blob)
		new.tap do |pc|
			pc.issuer_key_hash, tbs_blob = blob.unpack("a32a*")
			tbs_opaque, rest = TLS::Opaque.from_blob(tbs_blob, 2**24-1)
			unless rest == ""
				raise ArgumentError,
				      "Invalid blob (extra data after end of structure: #{rest.inspect}"
			end

			pc.tbs_certificate = tbs_opaque.value
		end
	end

	# Turn this structure into an encoded binary blob.
	#
	# @return [String]
	#
	# @raise [RuntimeError] if some of the fields in the structure aren't
	#   filled out.
	#
	def to_blob
		if @issuer_key_hash.nil?
			raise RuntimeError,
			      "issuer_key_hash is not set"
		end

		if @tbs_certificate.nil?
			raise RuntimeError,
			      "tbs_certificate is not set"
		end

		[
		 @issuer_key_hash,
		 TLS::Opaque.new(@tbs_certificate, 2**24-1).to_blob
		].pack("a32a*")
	end
end
