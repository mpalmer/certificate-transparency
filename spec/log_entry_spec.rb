require_relative './spec_helper'

describe "CT::LogEntry" do
	context ".new" do
		it "is happy to take nothing" do
			expect { CT::LogEntry.new }.to_not raise_error
		end
	end

	context ".from_json" do
		it "needs an argument" do
			expect { CT::LogEntry.from_json }.
			  to raise_error(ArgumentError)
		end

		it "pukes on arbitrary input" do
			expect { CT::LogEntry.from_json("OMG WTF") }.
			  to raise_error(JSON::ParserError)
		end

		it "takes a JSON document" do
			expect { CT::LogEntry.from_json(read_fixture_file("json_log_entry")) }.
			  to_not raise_error
		end

		let(:le) { CT::LogEntry.from_json(read_fixture_file("json_log_entry")) }

		it "produces a leaf input" do
			expect(le.leaf_input).to be_a(CT::MerkleTreeLeaf)
		end

		it "produces a chain" do
			expect(le.certificate_chain).to be_a(CT::CertificateChain)
		end

		it "fills the chain" do
			expect(le.certificate_chain.length).to be > 0
		end

		it "fills the chain with X509 certificates" do
			le.certificate_chain.each { |c| expect(c).to be_an(OpenSSL::X509::Certificate) }
		end

		it "round-trips correctly" do
			expect(le.to_json).to eq(read_fixture_file("json_log_entry").chomp)
		end
	end
end
