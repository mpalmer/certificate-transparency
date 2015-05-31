# An RFC6962 MerkleTreeLeaf structure
#
# Use {.from_blob} if you have an encoded MTL you wish to decode, or
# else create a new instance, pass in a `TimestampedEntry` object via
# `#timestamped_entry=`, and then call `#to_blob` to get the encoded MTL.
#
class CertificateTransparency::MerkleTreeLeaf
	attr_reader :timestamped_entry

	# Return a new MerkleTreeLeaf instance, from a binary blob of data.
	# Raises an ArgumentError if the blob is invalid in some way.
	#
	# @param blob [String]
	#
	# @return [CertificateTransparency::MerkleTreeLeaf]
	#
	def self.from_blob(blob)
		new.tap do |mtl|
			mtl.version, leaf_type, te = blob.unpack("CCa*")
			unless leaf_type == ::CertificateTransparency::MerkleLeafType[:timestamped_entry]
				raise ArgumentError,
				      "Unknown leaf type in blob"
			end

			mtl.timestamped_entry =
			     ::CertificateTransparency::TimestampedEntry.from_blob(te)
		end
	end

	# Instantiate a new MerkleTreeLeaf.
	#
	def initialize
		@version   = ::CertificateTransparency::Version[:v1]
		@leaf_type = ::CertificateTransparency::MerkleLeafType[:timestamped_entry]
	end

	# Set the version of the MerkleTreeLeaf structure to create.  At present,
	# only `:v1` is supported, so there isn't much point in ever calling this
	# method.
	#
	# @param v [Symbol]
	#
	# @return void
	#
	def version=(v)
		@version = case v
		when Symbol
			::CertificateTransparency::Version[v]
		when Integer
			v
		else
			nil
		end

		if @version.nil? or !::CertificateTransparency::Version.values.include?(@version)
			raise ArgumentError,
			      "Invalid version #{v.inspect}"
		end
	end

	# Return a symbol indicating the version of the MerkleTreeLeaf structure
	# represented by this object.  At present, only `:v1` is supported.
	#
	# @return Symbol
	#
	def version
		::CertificateTransparency::Version.invert[@version]
	end

	# Set the leaf type of the MerkleTreeLeaf structure.  At present, only
	# `:timestamped_entry` is supported, so there isn't much point in ever
	# calling this method.
	#
	# @param lt [Symbol]
	#
	# @return void
	#
	def leaf_type=(lt)
		@leaf_type = ::CertificateTransparency::MerkleLeafType[lt]

		if @leaf_type.nil?
			raise ArgumentError,
			      "Invalid leaf_type #{lt.inspect}"
		end
	end

	# Return a symbol indicating the leaf type of the MerkleTreeLeaf
	# structure represented by this object.  At present, only
	# `:timestamped_entry` is supported.
	#
	# @return Symbol
	#
	def leaf_type
		::CertificateTransparency::MerkleLeafType.invert[@leaf_type]
	end

	# Set the TimestampedEntry element for this MerkleTreeLeaf.  It must be
	# an instance of CertificateTransparency::TimestampedEntry, or an
	# ArgumentError will be raised.
	#
	# @param te [CertificateTransparency::TimestampedEntry]
	#
	# @return void
	#
	def timestamped_entry=(te)
		unless te.is_a? ::CertificateTransparency::TimestampedEntry
			raise ArgumentError,
			      "Wasn't passed a TimestampedEntry (got a #{te.class})"
		end

		@timestamped_entry = te
	end

	# Generate a binary blob representing this MerkleTreeLeaf structure.
	#
	# @return [String]
	#
	def to_blob
		if @timestamped_entry.nil?
			raise RuntimeError,
			      "timestamped_entry has not been set"
		end

		[@version, @leaf_type, @timestamped_entry.to_blob].pack("CCa*")
	end
end
