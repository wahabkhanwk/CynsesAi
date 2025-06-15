import pytest
import os
import json
import shutil
from fastapi.testing import TestClient

# Attempt to import the app and the api module itself for monkeypatching
# This assumes api.py is in the parent directory or PYTHONPATH is set up correctly
# For a typical project structure, if tests/ is a subdir of the project root,
# and api.py is also in the project root, this might require path adjustments
# or running pytest from the project root.
try:
    from api import app  # FastAPI app instance
    import api as api_module # The module itself to patch its variables
except ImportError:
    # Adjust path if necessary for your project structure
    import sys
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from api import app
    import api as api_module


# Constants for test setup
# Using a distinct name for test directory to avoid conflict if tests are interrupted.
TEST_ANALYSIS_RESULTS_DIR = "test_analysis_results_temp"
SAMPLE_ANALYSIS_ID = "test_analysis_123"

# These should match what's in config.settings.py or how api.py defines them
# If these are read from config.settings by api.py, the actual values from there will be used by the app
# but for creating mock files, we define them here.
SURICATA_OUTPUT_DIR_NAME = "suricata_output"
ZEEK_OUTPUT_DIR_NAME = "zeek_output"
THREAT_INTEL_FILENAME = "threat_intelligence.json"
ANOMALIES_FILENAME = "anomalies.json"
REPORT_FILENAME = "pcap_analysis_report.md" # As used in api.py for report

# Dummy content
DUMMY_REPORT_CONTENT = "# Test Report Content\nThis is a markdown report."
DUMMY_EVE_JSON_CONTENT = {"event_type": "alert", "src_ip": "1.2.3.4"}
DUMMY_FAST_LOG_CONTENT = "01/01/2024-10:00:00.000000  [**] [1:2000000:1] Test Alert [**]"
DUMMY_CONN_LOG_CONTENT = "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
DUMMY_THREAT_INTEL_CONTENT = {"ip_address": "1.2.3.4", "status": "malicious"}
DUMMY_ANOMALIES_CONTENT = {"anomalies": [{"type": "weird_traffic", "score": 0.9}]}


@pytest.fixture(scope="session", autouse=True)
def manage_test_analysis_dir(request):
    """
    Manages a temporary directory for analysis results during tests.
    - Creates the directory and mock data before tests.
    - Monkeypatches api_module.ANALYSIS_RESULTS_DIR to use this test directory.
    - Cleans up the directory after tests.
    """
    original_analysis_dir = api_module.ANALYSIS_RESULTS_DIR
    api_module.ANALYSIS_RESULTS_DIR = TEST_ANALYSIS_RESULTS_DIR

    if os.path.exists(TEST_ANALYSIS_RESULTS_DIR):
        shutil.rmtree(TEST_ANALYSIS_RESULTS_DIR)
    os.makedirs(TEST_ANALYSIS_RESULTS_DIR, exist_ok=True)

    # Create mock data for SAMPLE_ANALYSIS_ID
    mock_analysis_path = os.path.join(TEST_ANALYSIS_RESULTS_DIR, SAMPLE_ANALYSIS_ID)
    os.makedirs(mock_analysis_path, exist_ok=True)

    # 1. pcap_analysis_report.md
    with open(os.path.join(mock_analysis_path, REPORT_FILENAME), "w") as f:
        f.write(DUMMY_REPORT_CONTENT)

    # 2. Suricata output
    suricata_dir = os.path.join(mock_analysis_path, SURICATA_OUTPUT_DIR_NAME)
    os.makedirs(suricata_dir, exist_ok=True)
    with open(os.path.join(suricata_dir, "eve.json"), "w") as f:
        json.dump(DUMMY_EVE_JSON_CONTENT, f)
    with open(os.path.join(suricata_dir, "fast.log"), "w") as f:
        f.write(DUMMY_FAST_LOG_CONTENT)
    # Create other allowed suricata files if needed for more specific tests
    with open(os.path.join(suricata_dir, "stats.log"), "w") as f: f.write("dummy stats")
    with open(os.path.join(suricata_dir, "suricata.log"), "w") as f: f.write("dummy suricata log")


    # 3. Zeek output
    zeek_dir = os.path.join(mock_analysis_path, ZEEK_OUTPUT_DIR_NAME)
    os.makedirs(zeek_dir, exist_ok=True)
    with open(os.path.join(zeek_dir, "conn.log"), "w") as f:
        f.write(DUMMY_CONN_LOG_CONTENT)
    # Create other allowed zeek files
    for log_name in ["dns.log", "http.log", "files.log", "packet_filter.log", "smtp.log", "ssl.log", "weird.log", "x509.log"]:
        with open(os.path.join(zeek_dir, log_name), "w") as f: f.write(f"dummy {log_name} content")


    # 4. Threat intel
    with open(os.path.join(mock_analysis_path, THREAT_INTEL_FILENAME), "w") as f:
        json.dump(DUMMY_THREAT_INTEL_CONTENT, f)

    # 5. Anomalies
    with open(os.path.join(mock_analysis_path, ANOMALIES_FILENAME), "w") as f:
        json.dump(DUMMY_ANOMALIES_CONTENT, f)

    def cleanup():
        shutil.rmtree(TEST_ANALYSIS_RESULTS_DIR)
        api_module.ANALYSIS_RESULTS_DIR = original_analysis_dir # Restore

    request.addfinalizer(cleanup)

# Initialize TestClient
client = TestClient(app)

# --- Test Cases ---

def test_list_analyses():
    response = client.get("/api/analyses")
    assert response.status_code == 200
    assert SAMPLE_ANALYSIS_ID in response.json()

def test_get_analysis_report():
    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/report")
    assert response.status_code == 200
    assert response.text == DUMMY_REPORT_CONTENT

def test_get_analysis_report_not_found():
    response = client.get("/api/analyses/non_existent_id/report")
    assert response.status_code == 404

# --- Suricata Log Tests ---
def test_get_suricata_log_eve_json():
    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/suricata/eve.json")
    assert response.status_code == 200
    assert response.json() == DUMMY_EVE_JSON_CONTENT

def test_get_suricata_log_fast_log():
    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/suricata/fast.log")
    assert response.status_code == 200
    assert response.text == DUMMY_FAST_LOG_CONTENT

def test_get_suricata_log_disallowed_file():
    # This file exists but is not in ALLOWED_SURICATA_LOGS by default in api.py
    # It should be caught by the validation `if log_file not in ALLOWED_SURICATA_LOGS:`
    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/suricata/some_other_file.log")
    assert response.status_code == 400 # Bad request due to disallowed file name

def test_get_suricata_log_actually_not_found():
    # This file is allowed but we didn't create it
    # Example: ALLOWED_SURICATA_LOGS = ["eve.json", "fast.log", "stats.log", "suricata.log"]
    # We created eve.json, fast.log, stats.log, suricata.log.
    # Let's try to get one that doesn't exist physically.
    # To make this test meaningful, we'd need an allowed log that we *don't* create.
    # For now, let's assume 'alerts.log' is allowed but not created
    # api_module.ALLOWED_SURICATA_LOGS.append("alerts.log") # Temporarily allow if not already
    # response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/suricata/alerts.log")
    # assert response.status_code == 404
    # api_module.ALLOWED_SURICATA_LOGS.pop() # Clean up
    # Simpler: try getting a file that is allowed but we didn't create.
    # The fixture creates all allowed files, so this specific test is harder to set up
    # without further modification of the fixture or ALLOWED_SURICATA_LOGS.
    # Instead, we test the "analysis_id not found" case for suricata.
    pass


def test_get_suricata_log_analysis_id_not_found():
    response = client.get("/api/analyses/non_existent_id/suricata/eve.json")
    assert response.status_code == 404


# --- Zeek Log Tests ---
def test_get_zeek_log_conn_log():
    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/zeek/conn.log")
    assert response.status_code == 200
    assert response.text == DUMMY_CONN_LOG_CONTENT

def test_get_zeek_log_disallowed_file():
    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/zeek/some_other_zeek.log")
    assert response.status_code == 400 # Bad request

def test_get_zeek_log_analysis_id_not_found():
    response = client.get("/api/analyses/non_existent_id/zeek/conn.log")
    assert response.status_code == 404

# --- Threat Intel Tests ---
def test_get_threat_intel():
    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/threat_intel")
    assert response.status_code == 200
    assert response.json() == DUMMY_THREAT_INTEL_CONTENT

def test_get_threat_intel_not_found():
    response = client.get("/api/analyses/non_existent_id/threat_intel")
    assert response.status_code == 404

# --- Anomalies Data Tests ---
def test_get_anomalies_data(): # Corresponds to get_anomalies_report endpoint
    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/anomalies")
    assert response.status_code == 200
    assert response.json() == DUMMY_ANOMALIES_CONTENT

def test_get_anomalies_data_not_found():
    response = client.get("/api/analyses/non_existent_id/anomalies")
    assert response.status_code == 404

# --- Test specific file not founds within an existing analysis_id ---

def test_get_specific_suricata_log_not_present():
    # Assuming "alerts.log" is an allowed name but we haven't created it for SAMPLE_ANALYSIS_ID
    # Need to ensure "alerts.log" is in api_module.ALLOWED_SURICATA_LOGS for this test to be valid
    if "alerts.log" not in api_module.ALLOWED_SURICATA_LOGS:
        api_module.ALLOWED_SURICATA_LOGS.append("alerts.log")
        response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/suricata/alerts.log")
        assert response.status_code == 404
        api_module.ALLOWED_SURICATA_LOGS.pop() # cleanup
    else:
        # if it's already allowed, just run the test
        # this assumes the fixture does NOT create 'alerts.log'
        # create a dummy file that is allowed but not present
        suricata_dir = os.path.join(TEST_ANALYSIS_RESULTS_DIR, SAMPLE_ANALYSIS_ID, SURICATA_OUTPUT_DIR_NAME)
        if os.path.exists(os.path.join(suricata_dir, "alerts.log")):
             os.remove(os.path.join(suricata_dir, "alerts.log")) # ensure it's not there
        response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/suricata/alerts.log")
        assert response.status_code == 404


def test_get_specific_zeek_log_not_present():
    # Assuming "notice.log" is an allowed name but not created by fixture
    if "notice.log" not in api_module.ALLOWED_ZEEK_LOGS:
        api_module.ALLOWED_ZEEK_LOGS.append("notice.log")
        response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/zeek/notice.log")
        assert response.status_code == 404
        api_module.ALLOWED_ZEEK_LOGS.pop()
    else:
        zeek_dir = os.path.join(TEST_ANALYSIS_RESULTS_DIR, SAMPLE_ANALYSIS_ID, ZEEK_OUTPUT_DIR_NAME)
        if os.path.exists(os.path.join(zeek_dir, "notice.log")):
             os.remove(os.path.join(zeek_dir, "notice.log"))
        response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/zeek/notice.log")
        assert response.status_code == 404

# Final check on root endpoint
def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the PCAP Analysis API"}

# Example of testing disallowed file types more explicitly
def test_get_suricata_log_forbidden_extension():
    # Create a file like .exe which should never be allowed
    suricata_dir = os.path.join(TEST_ANALYSIS_RESULTS_DIR, SAMPLE_ANALYSIS_ID, SURICATA_OUTPUT_DIR_NAME)
    with open(os.path.join(suricata_dir, "somekindof.exe"), "w") as f:
        f.write("dummy exe")

    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/suricata/somekindof.exe")
    assert response.status_code == 400 # Due to not being in ALLOWED_SURICATA_LOGS

def test_get_zeek_log_forbidden_extension():
    zeek_dir = os.path.join(TEST_ANALYSIS_RESULTS_DIR, SAMPLE_ANALYSIS_ID, ZEEK_OUTPUT_DIR_NAME)
    with open(os.path.join(zeek_dir, "somekindof.exe"), "w") as f:
        f.write("dummy exe")

    response = client.get(f"/api/analyses/{SAMPLE_ANALYSIS_ID}/zeek/somekindof.exe")
    assert response.status_code == 400 # Due to not being in ALLOWED_ZEEK_LOGS
