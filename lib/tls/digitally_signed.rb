require 'openssl'

unless OpenSSL::PKey::EC.instance_methods.include?(:private?)
	OpenSSL::PKey::EC.class_eval("alias_method :private?, :private_key?")
end

# Create a `DigitallySigned` struct, as defined by RFC5246 s4.7, and adapted
# for the CertificateTransparency system (that is, ECDSA using the NIST
# P-256 curve is the only signature algorithm supported, and SHA-256 is the
# only hash algorithm supported).
#
class TLS::DigitallySigned
	# Create a new `DigitallySigned` struct.
	#
	# Takes a number of named options:
	#
	# * `:key` -- (required) An instance of `OpenSSL::PKey::PKey`.  If you
	#   pass in `:blob` as well, then this can be either a public key or a
	#   private key (because you only need a public key for validating a
	#   signature), but if you only pass in `:content`, you must provide a
	#   private key here.
	#
	#   This key *must* be generated with the NIST P-256 curve (known to
	#   OpenSSL as `prime256v1`), or be an RSA key of at least 2048 bits, in
	#   order to be compliant with the CT spec.  However, we can't validate
	#   some of those criteria, so it's up to you to make sure you do it
	#   right.
	#
	# * `:content` -- (required) The content to sign, or verify the signature
	#   of.  This can be any string.
	#
	# * `:blob` -- An existing encoded `DigitallySigned` struct you'd like to
	#   have decoded and verified against `:content` with `:key`.
	#
	# Raises an `ArgumentError` if you try to pass in anything that doesn't
	# meet the rather stringent requirements.
	#
	def self.from_blob(blob)
		hash_algorithm, signature_algorithm, sig_blob = blob.unpack("CCa*")

		unless ::TLS::SignatureAlgorithm.values.include?(signature_algorithm)
			raise ArgumentError,
			      "invalid signature type specified (#{signature_algorithm})"
		end

		if hash_algorithm != ::TLS::HashAlgorithm[:sha256]
			raise ArgumentError,
			      "Hash algorithm specified in blob is not SHA256"
		end

		sig, rest = ::TLS::Opaque.from_blob(sig_blob, 2**16-1)
		signature = sig.value

		TLS::DigitallySigned.new.tap do |ds|
			ds.hash_algorithm = hash_algorithm
			ds.signature_algorithm = signature_algorithm
			ds.signature = signature
		end
	end

	attr_accessor :content, :hash_algorithm, :signature_algorithm, :signature
	attr_reader :key

	# Set the key for this instance.
	#
	# @param k [OpenSSL::PKey::PKey] a key to verify or generate the signature.
	#   If you only want to verify an existing signature (ie you created this
	#   instance via {.from_blob}, then this key can be a public key.
	#   Otherwise, if you want to generate a new signature, you must pass in
	#   a private key.
	#
	# @return void
	#
	# @raise [ArgumentError] if you pass in a key that isn't of the
	#   appropriate type.
	#
	def key=(k)
		unless k.is_a?(OpenSSL::PKey::PKey)
			raise ArgumentError,
			      "Key must be an instance of OpenSSL::PKey::PKey (got a #{k.class})"
		end

		@key = k
	end

	# Return a binary string which represents a `DigitallySigned` struct of
	# the content passed in.
	#
	def to_blob
		if @key.nil?
			raise RuntimeError,
			      "No key has been supplied"
		end
		begin
			@signature ||= @key.sign(OpenSSL::Digest::SHA256.new, @content)
		rescue ArgumentError
			raise RuntimeError,
			      "Must have a private key in order to make a signature"
		end

		[
			@hash_algorithm,
			@signature_algorithm,
			@signature.length,
			@signature
		].pack("CCna*").force_encoding("BINARY")
	end

	# Verify whether or not the `signature` struct given is a valid signature
	# for the key/content/blob combination provided to the constructor.
	#
	def valid?
		if @key.nil?
			raise RuntimeError,
			      "No key has been specified"
		end

		if @signature.nil?
			raise RuntimeError,
			      "No signature is available yet"
		end

		if @content.nil?
			raise RuntimeError,
			      "No content has been specified yet"
		end

		@key.verify(OpenSSL::Digest::SHA256.new, @signature, @content)
	end
end
