"""On-demand Web Capture (inventory enrichment of known HTTP interfaces)."""
from .manager import web_capture_manager
from .runner import CaptureContext, delete_web_capture, run_web_capture

__all__ = ["web_capture_manager", "CaptureContext", "run_web_capture", "delete_web_capture"]
