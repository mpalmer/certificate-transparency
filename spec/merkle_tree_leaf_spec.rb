require_relative 'spec_helper'

describe CT::MerkleTreeLeaf do
	context ".from_blob" do
		let(:mtl) { CT::MerkleTreeLeaf.from_blob(fixture_file("leaf_input")) }

		it "creates a MerkleTreeLeaf" do
			expect(mtl).to be_a(CT::MerkleTreeLeaf)
		end

		it "has the right version" do
			expect(mtl.version).to eq(:v1)
		end

		it "has the right leaf type" do
			expect(mtl.leaf_type).to eq(:timestamped_entry)
		end

		it "has a timestamped entry" do
			expect(mtl.timestamped_entry).to be_a(CT::TimestampedEntry)
		end

		it "round-trips correctly" do
			expect(mtl.to_blob).to eq(fixture_file("leaf_input"))
		end
	end
end
