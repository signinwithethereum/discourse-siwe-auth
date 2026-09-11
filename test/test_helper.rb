# frozen_string_literal: true

module PluginTestGems
  module_function

  def activate(name, version)
    loaded = Gem.loaded_specs[name]
    return if loaded&.version == Gem::Version.new(version)

    begin
      gem name, version
      return
    rescue Gem::LoadError
      # Discourse may have installed the gem outside the standalone GEM_PATH.
    end

    pattern = File.expand_path("../gems/*/specifications/#{name}-#{version}*.gemspec", __dir__)
    spec_path = Dir[pattern].max
    raise LoadError, "Install plugin gem #{name} #{version} before running this test" unless spec_path

    gems_path = File.dirname(File.dirname(spec_path))
    Gem.path << gems_path unless Gem.path.include?(gems_path)
    Gem::Specification.load(spec_path).activate
  end
end
