from fastapi import FastAPI, File, UploadFile, HTTPException
import shutil
import os
import uuid # For unique IDs
from starlette.responses import FileResponse
from main import perform_pcap_analysis # Import the analysis function
from config.settings import (
    SURICATA_OUTPUT_DIR_NAME,
    ZEEK_OUTPUT_DIR_NAME,
    THREAT_INTEL_FILENAME,
    ANOMALIES_FILENAME,
)

app = FastAPI(title="PCAP Analysis API", version="0.1.0")

# Create uploads directory if it doesn't exist
UPLOADS_DIR = "uploads"
os.makedirs(UPLOADS_DIR, exist_ok=True)

ANALYSIS_RESULTS_DIR = "analysis_results"
os.makedirs(ANALYSIS_RESULTS_DIR, exist_ok=True)

# Allowed log file names
ALLOWED_SURICATA_LOGS = ["eve.json", "fast.log", "stats.log", "suricata.log"]
ALLOWED_ZEEK_LOGS = [
    "conn.log", "dns.log", "files.log", "http.log", "packet_filter.log",
    "smtp.log", "ssl.log", "weird.log", "x509.log"
]


@app.get("/")
async def root():
    return {"message": "Welcome to the PCAP Analysis API"}

@app.post("/api/upload_pcap")
async def upload_pcap(file: UploadFile = File(...)):
    # Generate a unique ID for this analysis session
    analysis_id = str(uuid.uuid4())

    # Create a specific directory for this uploaded PCAP's results
    pcap_upload_path = os.path.join(UPLOADS_DIR, analysis_id) # This is where the original PCAP is saved
    os.makedirs(pcap_upload_path, exist_ok=True)

    file_path = os.path.join(pcap_upload_path, file.filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    finally:
        file.file.close()

    # Trigger analysis
    # This is a synchronous call. For long analyses, consider background tasks.
    # The perform_pcap_analysis function is expected to save results in ANALYSIS_RESULTS_DIR/analysis_id
    report_path, _ = perform_pcap_analysis(file_path, analysis_id)

    return {
        "message": f"PCAP file '{file.filename}' uploaded and analysis started.",
        "analysis_id": analysis_id,
        "saved_pcap_path": file_path, # Original pcap path
        "report_path": report_path, # Path to the markdown report
        "filename": file.filename
    }

@app.get("/api/analyses", summary="List all available analysis IDs")
async def list_analyses():
    """
    Retrieves a list of all analysis IDs for which results are available.
    Each ID corresponds to a previously uploaded and processed PCAP file.
    """
    if not os.path.exists(ANALYSIS_RESULTS_DIR) or not os.path.isdir(ANALYSIS_RESULTS_DIR):
        return []
    try:
        analysis_ids = [
            d for d in os.listdir(ANALYSIS_RESULTS_DIR)
            if os.path.isdir(os.path.join(ANALYSIS_RESULTS_DIR, d))
        ]
        return analysis_ids
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing analyses: {str(e)}")

@app.get("/api/analyses/{analysis_id}/report", summary="Get analysis report")
async def get_analysis_report(analysis_id: str):
    """
    Retrieves the main analysis report in Markdown format for the given analysis ID.
    """
    report_path = os.path.join(ANALYSIS_RESULTS_DIR, analysis_id, "pcap_analysis_report.md")
    if os.path.exists(report_path):
        return FileResponse(report_path, media_type='text/markdown', filename="pcap_analysis_report.md")
    else:
        raise HTTPException(status_code=404, detail="Report not found.")

@app.get("/api/analyses/{analysis_id}/suricata/{log_file}", summary="Get Suricata log file")
async def get_suricata_log(analysis_id: str, log_file: str):
    """
    Retrieves a specific Suricata log file (e.g., eve.json, fast.log) for the given analysis ID.
    Allowed log files are: eve.json, fast.log, stats.log, suricata.log.
    """
    if log_file not in ALLOWED_SURICATA_LOGS:
        raise HTTPException(status_code=400, detail=f"Log file '{log_file}' is not allowed for Suricata.")

    file_path = os.path.join(ANALYSIS_RESULTS_DIR, analysis_id, SURICATA_OUTPUT_DIR_NAME, log_file)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='application/text', filename=log_file) # Adjust media type if specific (e.g. eve.json is application/json)
    else:
        raise HTTPException(status_code=404, detail=f"Suricata log file '{log_file}' not found.")

@app.get("/api/analyses/{analysis_id}/zeek/{log_file}", summary="Get Zeek log file")
async def get_zeek_log(analysis_id: str, log_file: str):
    """
    Retrieves a specific Zeek log file for the given analysis ID.
    Allowed log files include: conn.log, dns.log, http.log, etc.
    """
    if log_file not in ALLOWED_ZEEK_LOGS:
        raise HTTPException(status_code=400, detail=f"Log file '{log_file}' is not allowed for Zeek.")

    file_path = os.path.join(ANALYSIS_RESULTS_DIR, analysis_id, ZEEK_OUTPUT_DIR_NAME, log_file)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='application/text', filename=log_file) # Zeek logs are typically plain text
    else:
        raise HTTPException(status_code=404, detail=f"Zeek log file '{log_file}' not found.")

@app.get("/api/analyses/{analysis_id}/threat_intel", summary="Get threat intelligence data")
async def get_threat_intelligence(analysis_id: str):
    """
    Retrieves the threat intelligence data (raw and LLM analysis) in JSON format
    for the given analysis ID.
    """
    file_path = os.path.join(ANALYSIS_RESULTS_DIR, analysis_id, THREAT_INTEL_FILENAME)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="application/json", filename=THREAT_INTEL_FILENAME)
    else:
        raise HTTPException(status_code=404, detail="Threat intelligence report not found.")

@app.get("/api/analyses/{analysis_id}/anomalies", summary="Get anomaly detection data")
async def get_anomalies_report(analysis_id: str): # Renamed function to avoid conflict if I add a different get_anomalies_data
    """
    Retrieves the anomaly detection data (anomalies, summary, status) in JSON format
    for the given analysis ID.
    """
    file_path = os.path.join(ANALYSIS_RESULTS_DIR, analysis_id, ANOMALIES_FILENAME)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="application/json", filename=ANOMALIES_FILENAME)
    else:
        raise HTTPException(status_code=404, detail="Anomalies report not found.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
