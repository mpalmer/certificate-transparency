# The base module of everything related to Certificate Transparency.
module CertificateTransparency
	# RFC6962 s3.1
	LogEntryType = {
		:x509_entry => 0,
		:precert_entry => 1
	}

	# RFC6962 s3.4
	MerkleLeafType = {
		:timestamped_entry => 0
	}

	# RFC6962 s3.2
	SignatureType = {
		:certificate_timestamp => 0,
		:tree_hash             => 1
	}

	# RFC6962 s3.2
	Version = {
		:v1 => 0
	}
end

unless Kernel.const_defined?(:CT)
	#:nodoc:
	CT = CertificateTransparency
end

require_relative 'certificate-transparency/extensions/string'
require_relative 'certificate-transparency/extensions/time'

require_relative 'certificate-transparency/merkle_tree_leaf'
require_relative 'certificate-transparency/pre_cert'
require_relative 'certificate-transparency/signed_tree_head'
require_relative 'certificate-transparency/timestamped_entry'
