require_relative 'spec_helper'

describe CT::TimestampedEntry do
	context ".from_blob with a x509_entry" do
		let(:te) { CT::TimestampedEntry.from_blob(fixture_file("timestamped_entry")) }

		it "creates a TimestampedEntry" do
			expect(te).to be_a(CT::TimestampedEntry)
		end

		it "has the right time" do
			expect(te.timestamp).to eq(Time.at(1415251876.119))
		end

		it "has the right time in milliseconds" do
			expect(te.timestamp.ms).to eq(1415251876119)
		end

		it "has the right entry type" do
			expect(te.entry_type).to eq(:x509_entry)
		end

		it "has no precert_entry" do
			expect(te.precert_entry).to be(nil)
		end

		it "has an x509_entry" do
			expect(te.x509_entry).to be_a(OpenSSL::X509::Certificate)
		end

		it "round-trips correctly" do
			expect(te.to_blob).to eq(fixture_file("timestamped_entry"))
		end
	end

	context ".from_blob with a precert_entry" do
		let(:te) { CT::TimestampedEntry.from_blob(fixture_file("timestamped_entry_precert")) }

		it "creates a TimestampedEntry" do
			expect(te).to be_a(CT::TimestampedEntry)
		end

		it "has the right time" do
			expect(te.timestamp).to eq(Time.at(1423491905.275))
		end

		it "has the right time in milliseconds" do
			expect(te.timestamp.ms).to eq(1423491905275)
		end

		it "has the right entry type" do
			expect(te.entry_type).to eq(:precert_entry)
		end

		it "has no x509_entry" do
			expect(te.x509_entry).to be(nil)
		end

		it "has a precert_entry" do
			expect(te.precert_entry).to be_a(CT::PreCert)
		end

		it "round-trips correctly" do
			expect(te.to_blob).to eq(fixture_file("timestamped_entry_precert"))
		end
	end
end
