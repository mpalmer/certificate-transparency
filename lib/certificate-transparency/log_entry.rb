require 'json'
require 'tls'

# An element of a CT get-entries array (RFC6962 s4.6).  Note that this is
# **not** the `LogEntry` type defined in RFC6962 s3.1, because that type is
# never actually used anywhere, so I stole its name.
#
class CertificateTransparency::LogEntry
	attr_accessor :leaf_input
	attr_accessor :extra_data

	# Create a new LogEntry instance from a single member of the
	# `"entries"` array returned by `/ct/v1/get-entries`.
	#
	def self.from_json(json)
		doc = JSON.parse(json)

		self.new.tap do |sth|
			le_blob = doc["leaf_input"].unpack("m").first
			sth.leaf_input = CT::MerkleTreeLeaf.from_blob(le_blob)

			sth.extra_data = []
			ed_blob = doc["extra_data"].unpack("m").first
			if sth.leaf_input.timestamped_entry.entry_type == :precert_entry
				pre_cert_blob, ed_blob = TLS::Opaque.from_blob(ed_blob, 2**24-1)

				sth.extra_data << OpenSSL::X509::Certificate.new(pre_cert_blob.value)
			end

			ed_blob, rest = TLS::Opaque.from_blob(ed_blob, 2**24-1)
			unless rest.empty?
				raise ArgumentError,
				      "Unexpected garbage after certificate_chain: #{rest.inspect}"
			end

			ed_blob = ed_blob.value
			until ed_blob.empty?
				cert_blob, ed_blob = TLS::Opaque.from_blob(ed_blob, 2**24-1)
				sth.extra_data << OpenSSL::X509::Certificate.new(cert_blob.value)
			end
		end
	end
end
