require 'yaml'

project.name = 'ECDSATest'

application_for :ios, '10.0' do |target|
  target.name = 'ECDSATest'
  target.all_configurations.each do |config|
    config.product_bundle_identifier = 'com.awesomecompany.ecdsatest'
  end

  unit_tests_for target do |tests|
    tests.all_configurations.each do |config|
      config.product_bundle_identifier = 'com.awesomecompany.ecdsatest.tests'
    end
  end

  swiftlint_file = '${BUILT_PRODUCTS_DIR}/SwiftLint-touched.txt'
  swiftlint_phase_script = <<-SWIFTLINT
  trap 'exit 0;' INT
  "${PODS_ROOT}"/SwiftLint/swiftlint && touch #{swiftlint_file}
  SWIFTLINT
  target.pre_shell_script_build_phase('SwiftLint', swiftlint_phase_script) do |phase|
    config_excludes = YAML.load_file('.swiftlint.yml')['excluded']
                          .map { |filename| filename.end_with?('.swift') ? [filename] : Dir["#{filename}/**/*.swift"] }
                          .flatten
    file_list = (Dir['**/*.swift'] - config_excludes).sort
    phase.input_paths = file_list.map { |f| "${SRCROOT}/#{f}" }
    phase.output_paths = [swiftlint_file]
  end

  rswift_file = '$SRCROOT/ECDSATest/Resources/Generated/R.generated.swift'
  rswift_generate_script = <<-GENERATE
  "${PODS_ROOT}/R.swift/rswift" generate "#{rswift_file}"
  GENERATE
  target.pre_shell_script_build_phase('R.swift generate', rswift_generate_script) do |phase|
    phase.input_paths = ['$TEMP_DIR/rswift-lastrun']
    phase.output_paths = [rswift_file]
  end
end

project.after_save do
  system "rm -rf \"#{project.name}.xcodeproj/xcshareddata/xcschemes\""
end
