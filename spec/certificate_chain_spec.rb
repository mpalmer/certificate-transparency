require_relative 'spec_helper'

describe CT::CertificateChain do
	context ".from_blob" do
		let(:cc) { CT::CertificateChain.from_blob(read_fixture_file("cert_chain")) }

		it "creates a CertificateChain" do
			expect(cc).to be_a(CT::CertificateChain)
		end

		it "iterates" do
			expect(cc).to respond_to(:each)
		end

		it "contains X509 Certificates" do
			cc.each { |c| expect(c).to be_an(OpenSSL::X509::Certificate) }
		end

		it "round-trips correctly" do
			expect(cc.to_blob).to eq(read_fixture_file("cert_chain"))
		end
	end
end
