# Spectra
# List available targets
python3 run_property_tests.py --list-targets

# List available properties
python3 run_property_tests.py --list-properties --mode client

# Run a single test
python3 run_property_tests.py --mode client --target openssl --property C1 --verbose

# Run all tests with report generation
python3 run_property_tests.py --mode client --target openssl --property all \
    --html reports/openssl.html --json reports/openssl.json
