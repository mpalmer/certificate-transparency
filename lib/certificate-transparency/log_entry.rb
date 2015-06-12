require 'json'
require 'tls'

# An element of a CT get-entries array (RFC6962 s4.6).
#
# @note This is **not** the `LogEntry` type defined in RFC6962 s3.1, because
#   that type is never actually used anywhere, so I stole its name.
#
# @note Unlike most other classes, the instance methods on this type are
#   *not* a 1:1 mapping to the elements of the source data structure.  The
#   `extra_data` key in the JSON is a grotty amalgam of several other
#   things.  Those pieces are available via {#certificate_chain} and
#   {#precertificate}.
#
class CertificateTransparency::LogEntry
	# @return [CT::MerkleTreeLeaf]
	#
	attr_accessor :leaf_input

	# @return [CT::CertificateChain]
	#
	attr_accessor :certificate_chain

	# The precertificate if this log entry is for a precert, or `nil`
	# otherwise.
	#
	# @return [OpenSSL::X509::Certificate]
	#
	attr_accessor :precertificate

	# Create a new LogEntry instance from a single member of the
	# `"entries"` array returned by `/ct/v1/get-entries`.
	#
	def self.from_json(json)
		doc = JSON.parse(json)

		self.new.tap do |sth|
			le_blob = doc["leaf_input"].unpack("m").first
			sth.leaf_input = CT::MerkleTreeLeaf.from_blob(le_blob)

			ed_blob = doc["extra_data"].unpack("m").first

			if sth.leaf_input.timestamped_entry.entry_type == :precert_entry
				precert_blob, ed_blob = TLS::Opaque.from_blob(ed_blob, 2**24-1)

				sth.precertificate = OpenSSL::X509::Certificate.new(precert_blob.value)
			end

			sth.certificate_chain = CT::CertificateChain.from_blob(ed_blob)
		end
	end

	# Return a JSON string that represents this log entry, as it would
	# exist in a response from `/get-entries`.
	#
	# @return [String]
	#
	def to_json
		json = { :leaf_input => [leaf_input.to_blob].pack("m0") }

		ed_blob = ""

		if leaf_input.timestamped_entry.entry_type == :precert_entry
			ed_blob += TLS::Opaque.new(precertificate.to_der, 2**24-1).to_blob
		end

		ed_blob += certificate_chain.to_blob

		json[:extra_data] = [ed_blob].pack("m0")

		json.to_json
	end
end
