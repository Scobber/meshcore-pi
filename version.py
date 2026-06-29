# Shared version information for meshcore-pi components

MESHCORE_VERSION = "1.12.0"
MESHCORE_VERSION_DATE = "2026-06-28"
MESHCORE_BUILD_DATE = "28 Jun 2026"

# Protocol compatibility values used by companion/device query responses.
# This is intentionally independent from app version numbers.
MESHCORE_SUPPORTED_PROTOCOL_VERSION = 12
MESHCORE_MIN_CLIENT_PROTOCOL_VERSION = 3

# Backward-compatible alias used by existing code paths.
MESHCORE_FIRMWARE_VER_CODE = MESHCORE_SUPPORTED_PROTOCOL_VERSION


def firmware_version_tag():
    return f"v{MESHCORE_VERSION}"
