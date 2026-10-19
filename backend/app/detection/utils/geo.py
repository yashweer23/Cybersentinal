from math import asin, cos, isfinite, radians, sin, sqrt

from app.detection.base import label, raw


def coordinates(event):
    geo = raw(event).get("geo")
    if not isinstance(geo, dict):
        return None
    lat, lon = geo.get("latitude"), geo.get("longitude")
    if any(
        isinstance(x, bool) or not isinstance(x, (int, float)) or not isfinite(x)
        for x in (lat, lon)
    ):
        return None
    if not -90 <= lat <= 90 or not -180 <= lon <= 180:
        return None
    return {
        "latitude": lat,
        "longitude": lon,
        "city": label(geo.get("city")),
        "country": label(geo.get("country")),
    }


def haversine(a, b):
    lat1, lat2 = radians(a["latitude"]), radians(b["latitude"])
    dlat, dlon = lat2 - lat1, radians(b["longitude"] - a["longitude"])
    term = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    return 6371.0088 * 2 * asin(sqrt(min(1, max(0, term))))
