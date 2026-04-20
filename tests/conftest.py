import os
import tempfile

# osv_common reads GROUND_TRUTH_BUILD_PATH at import time
os.environ.setdefault("GROUND_TRUTH_BUILD_PATH", tempfile.mkdtemp(prefix="gt_build_"))
