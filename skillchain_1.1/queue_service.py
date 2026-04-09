# queue_service.py
import threading, time
from collections import deque
from algorand_service import anchor_hash

# In-memory queue — safe because it holds only hashes
_queue = deque()
_results = {}  # batch_id → results
_lock = threading.Lock()

def queue_batch(batch_id: str, jobs: list, institution: dict):
    with _lock:
        _results[batch_id] = {
            "status": "queued",
            "total": len(jobs),
            "processed": 0,
            "results": []
        }
        _queue.append({
            "batch_id": batch_id,
            "jobs": jobs,
            "institution": institution,
            "queued_at": time.time()
        })


def get_batch_status(batch_id: str) -> dict:
    with _lock:
        return _results.get(batch_id, {"error": "Batch not found"})

def _worker():
    """Background thread — drains the queue, anchors hashes on Algorand"""
    while True:
        batch = None
        with _lock:
            if _queue:
                batch = _queue.popleft()
        
        if not batch:
            time.sleep(2)
            continue

        batch_id = batch["batch_id"]
        institution = batch["institution"]

        for job in batch["jobs"]:
            if "error" in job:
                continue  # already failed at hash stage
            
            try:
                # This is all we're doing — anchoring a hash
                result = anchor_hash(
                    cert_hash=job["cert_hash"],
                    doc_type=job["doc_type"],
                    holder_name="",     # no name at issuance
                    institution=institution,
                    signature=job["signature"]
                )
                
                with _lock:
                    _results[batch_id]["processed"] += 1
                    _results[batch_id]["results"].append({
                        "filename": job["filename"],
                        "cert_hash": job["cert_hash"],
                        "tx_id": result["tx_id"],
                        "ipfs_cid": result["ipfs_cid"],
                        "claim_url": f"/claim/{job['cert_hash']}",
                        "status": "anchored"
                    })
                
                # Algorand needs ~4 seconds per tx for confirmation
                # Small sleep prevents hammering the node
                time.sleep(0.5)

            except Exception as e:
                with _lock:
                    _results[batch_id]["results"].append({
                        "filename": job["filename"],
                        "error": str(e),
                        "status": "anchor_failed"
                    })

        with _lock:
            _results[batch_id]["status"] = "complete"

# Start worker on app startup
_worker_thread = threading.Thread(target=_worker, daemon=True)
_worker_thread.start()