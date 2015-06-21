require_relative './spec_helper'

describe "CT::SignedTreeHead" do
	describe ".new" do
		it "is happy to take nothing" do
			expect { CT::SignedTreeHead.new }.to_not raise_error
		end
	end

	describe ".from_json" do
		it "needs an argument" do
			expect { CT::SignedTreeHead.from_json }.
			  to raise_error(ArgumentError)
		end

		it "pukes on arbitrary input" do
			expect { CT::SignedTreeHead.from_json("OMG WTF") }.
			  to raise_error(JSON::ParserError)
		end

		it "takes a JSON document" do
			expect { CT::SignedTreeHead.from_json(read_fixture_file("json_sth")) }.
			  to_not raise_error
		end

		let(:sth) { CT::SignedTreeHead.from_json(read_fixture_file("json_sth")) }

		it "records the tree size" do
			expect(sth.tree_size).to eq(4967961)
		end

		it "records the timestamp" do
			expect(sth.timestamp).to be_within(0.001).of(Time.at(1432858108.748))
		end
	end

	describe "#valid?" do
		context "raw EC key and signature" do
			let(:key) { read_fixture_file("rocketeer_pk").unbase64 }
			let(:sth) { CT::SignedTreeHead.from_json(read_fixture_file("json_sth")) }

			it "validates" do
				expect(sth.valid?(key)).to eq(true)
			end
		end

		context "parsed EC key and signature" do
			let(:key) do
				OpenSSL::PKey::EC.new(read_fixture_file("rocketeer_pk").unbase64)
			end
			let(:sth) do
				CT::SignedTreeHead.from_json(read_fixture_file("json_sth"))
			end

			it "validates" do
				expect(sth.valid?(key)).to eq(true)
			end
		end

		context "raw RSA key and signature" do
			let(:key) { read_fixture_file("rsa_pk").unbase64 }
			let(:sth) { CT::SignedTreeHead.from_json(read_fixture_file("rsa_signed_sth")) }

			it "validates" do
				expect(sth.valid?(key)).to eq(true)
			end
		end

		context "parsed RSA key and signature" do
			let(:key) do
				OpenSSL::PKey::RSA.new(read_fixture_file("rsa_pk").unbase64)
			end
			let(:sth) do
				CT::SignedTreeHead.from_json(read_fixture_file("rsa_signed_sth"))
			end

			it "validates" do
				expect(sth.valid?(key)).to eq(true)
			end
		end
	end
end
