require_relative 'spec_helper'

describe CT::PreCert do
	context ".from_blob" do
		let(:pc) { CT::PreCert.from_blob(read_fixture_file("pre_cert")) }

		it "creates a PreCert" do
			expect(pc).to be_a(CT::PreCert)
		end

		it "has the right issuer_key_hash" do
			expect(Digest::SHA256.hexdigest(pc.issuer_key_hash))
			  .to eq("106079e8c50915c0a5e74feff4f5b1e3ca9d5c0996545d29072b4c4086c69337")
		end

		it "has the right tbs_cert" do
			expect(Digest::SHA256.hexdigest(pc.tbs_certificate))
			  .to eq("9ec6b10b6e4a59f0ae0117b0e4a93479eced9bc55625601ad6a1c4a774eac61a")
		end

		it "round-trips correctly" do
			expect(pc.to_blob).to eq(read_fixture_file("pre_cert"))
		end
	end
end
