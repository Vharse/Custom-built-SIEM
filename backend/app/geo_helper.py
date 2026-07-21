import os
import ipaddress
import geoip2.database # type: ignore
import geoip2.errors
from functools import lru_cache


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/app/db_data/GeoLite2-City.mmdb'

try:
    _reader = geoip2.database.Reader(DB_PATH)
except FileNotFoundError:
    _reader = None
    print(f"CRITICAL: GeoIP database not found at {DB_PATH}")


@lru_cache(maxsize=1024)
def get_location(ip: str):
    """
    Enriches IP with location data and identifies internal network traffic.
    Uses LRU cache to optimize for high-frequency requests.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            return "INTERNAL_NETWORK"

        # Lookup Public Traffic
        if _reader is None:
            return "DATABASE_UNAVAILABLE"

        response = _reader.city(ip)
        city = response.city.name or "Unknown City"
        country = response.country.name or "Unknown Country"
        return f"{city}, {country}"

    except ValueError:
        return "INVALID_IP"
    except geoip2.errors.AddressNotFoundError:
        return "UNKNOWN_GEO"
    except Exception:
        return "UNKNOWN_GEO"


def close_geoip_reader():
    global _reader
    if _reader is not None:
        _reader.close()
        _reader = None