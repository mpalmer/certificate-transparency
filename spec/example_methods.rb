module ExampleMethods
	def fixture_file(f)
		File.read(File.expand_path("../fixtures/#{f}", __FILE__)).force_encoding("BINARY")
	end
end
