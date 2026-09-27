// CyberTrace AI — Interactive Forensic GeoMap Component
// =============================================================================
// Features:
//   - Leaflet interactive map with CartoDB Dark Matter & OpenStreetMap tiles
//   - Multi-hop MTA transmission route (Polyline path connecting hops)
//   - Forensic tactical markers:
//       * 🔴 Attributed Threat Origin (pulsing radar marker)
//       * 🟡 Intermediate MTA Relays
//       * 🟢 Target Mail Server (Inbox MX)
//   - Google Maps Integration:
//       * Satellite / Hybrid Google Maps embed view
//       * "View in Google Maps" direct link with GPS coordinates
//       * Optional custom Google Maps API key configuration
//   - Forensic popup tooltips with IP, Country, ASN, Reverse DNS, Trust Rating
// =============================================================================

import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';

// Fix Leaflet default marker icons in bundlers
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

// Custom SVG Pulsing Pins
function createCustomMarker(type = 'relay', number = 1) {
  const isOrigin = type === 'origin';
  const isTarget = type === 'target';

  const color = isOrigin ? '#dc2626' : isTarget ? '#16a34a' : '#f59e0b';
  const glowColor = isOrigin ? 'rgba(220, 38, 38, 0.4)' : isTarget ? 'rgba(22, 163, 74, 0.4)' : 'rgba(245, 158, 11, 0.4)';
  const label = isOrigin ? '🚨' : isTarget ? '🎯' : `${number}`;

  const html = `
    <div style="
      position: relative;
      display: flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
    ">
      <div style="
        position: absolute;
        width: 100%;
        height: 100%;
        border-radius: 50%;
        background: ${glowColor};
        animation: leafletPulse 2s infinite ease-out;
      "></div>
      <div style="
        position: relative;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        background: ${color};
        color: #ffffff;
        font-family: ui-monospace, monospace;
        font-weight: 800;
        font-size: 11px;
        display: flex;
        align-items: center;
        justify-content: center;
        border: 2px solid #ffffff;
        box-shadow: 0 2px 8px rgba(0,0,0,0.35);
      ">
        ${label}
      </div>
    </div>
    <style>
      @keyframes leafletPulse {
        0% { transform: scale(0.8); opacity: 1; }
        100% { transform: scale(2.2); opacity: 0; }
      }
    </style>
  `;

  return L.divIcon({
    html,
    className: 'cybertrace-custom-marker',
    iconSize: [32, 32],
    iconAnchor: [16, 16],
    popupAnchor: [0, -18],
  });
}

export default function InteractiveGeoMap({
  hops = [],
  originGeo = null,
  title = 'Geographic MTA Infrastructure Map',
  height = 380,
}) {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const markersRef = useRef([]);
  const polylineRef = useRef(null);

  const [activeLayer, setActiveLayer] = useState('dark'); // 'dark' | 'osm' | 'google'
  const [selectedHop, setSelectedHop] = useState(null);
  const [googleKey, setGoogleKey] = useState(
    () => localStorage.getItem('CYBERTRACE_GOOGLE_MAPS_KEY') || ''
  );
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [copiedCoords, setCopiedCoords] = useState(false);

  // Normalize points with valid lat & lon
  const points = [];

  // Add origin point first if available
  if (originGeo && typeof originGeo.lat === 'number' && typeof originGeo.lon === 'number' && (originGeo.lat !== 0 || originGeo.lon !== 0)) {
    points.push({
      ...originGeo,
      type: 'origin',
      title: 'Attributed Threat Origin',
      ip: originGeo.ip,
      hopNum: hops.length || 1,
    });
  }

  // Add intermediate hops if they have coordinates
  if (Array.isArray(hops)) {
    hops.forEach((hop, idx) => {
      const g = hop.geo || hop.ipIntelligence;
      if (g && typeof g.lat === 'number' && typeof g.lon === 'number' && (g.lat !== 0 || g.lon !== 0)) {
        // Avoid duplicate coordinates
        const isDuplicate = points.some(
          (p) => Math.abs(p.lat - g.lat) < 0.001 && Math.abs(p.lon - g.lon) < 0.001
        );
        if (!isDuplicate) {
          const isTarget = idx === 0;
          const isOrigin = idx === hops.length - 1;
          points.push({
            ip: hop.ip,
            host: hop.host || hop.fromHost || hop.ip,
            city: g.city,
            country: g.country,
            countryCode: g.countryCode,
            isp: g.isp,
            asn: g.asn,
            lat: g.lat,
            lon: g.lon,
            type: isOrigin ? 'origin' : isTarget ? 'target' : 'relay',
            title: isOrigin
              ? 'Attributed Threat Origin'
              : isTarget
              ? 'Target Mail Server (Inbox MX)'
              : `MTA Relay Hop #${idx + 1}`,
            hopNum: idx + 1,
            trust: hop.trust,
            reverseDns: hop.reverseDns,
          });
        }
      }
    });
  }

  // Fallback origin if no points exist yet
  const primaryPoint = points.find((p) => p.type === 'origin') || points[0] || {
    lat: 39.03,
    lon: -77.5,
    city: 'Ashburn',
    country: 'United States',
    ip: '198.51.100.1',
    type: 'origin',
    title: 'Estimated Threat Infrastructure',
  };

  // Initialize and update Leaflet Map
  useEffect(() => {
    if (activeLayer === 'google') return;
    if (!mapContainerRef.current) return;

    if (!mapInstanceRef.current) {
      const initialCenter = [primaryPoint.lat || 20, primaryPoint.lon || 0];
      const initialZoom = points.length > 1 ? 3 : 5;

      const map = L.map(mapContainerRef.current, {
        center: initialCenter,
        zoom: initialZoom,
        zoomControl: false,
        attributionControl: false,
      });

      L.control.zoom({ position: 'topright' }).addTo(map);

      // Attribution
      L.control
        .attribution({ position: 'bottomright', prefix: 'CyberTrace AI Forensics' })
        .addTo(map);

      mapInstanceRef.current = map;
    }

    const map = mapInstanceRef.current;

    // Tile Layer based on activeLayer
    map.eachLayer((layer) => {
      if (layer instanceof L.TileLayer) {
        map.removeLayer(layer);
      }
    });

    if (activeLayer === 'dark') {
      // CartoDB Dark Matter
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        subdomains: 'abcd',
      }).addTo(map);
    } else {
      // OpenStreetMap Standard
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
      }).addTo(map);
    }

    // Clear old markers
    markersRef.current.forEach((m) => map.removeLayer(m));
    markersRef.current = [];
    if (polylineRef.current) {
      map.removeLayer(polylineRef.current);
      polylineRef.current = null;
    }

    if (points.length > 0) {
      const latlngs = [];

      points.forEach((pt) => {
        const markerIcon = createCustomMarker(pt.type, pt.hopNum);
        const marker = L.marker([pt.lat, pt.lon], { icon: markerIcon }).addTo(map);

        const googleMapsUrl = `https://www.google.com/maps?q=${pt.lat},${pt.lon}`;

        const popupContent = `
          <div style="font-family: var(--font-ui, sans-serif); min-width: 220px; font-size: 12px; color: #0f172a;">
            <div style="font-weight: 800; font-size: 13px; margin-bottom: 4px; color: ${
              pt.type === 'origin' ? '#dc2626' : pt.type === 'target' ? '#16a34a' : '#d97706'
            }; display: flex; align-items: center; gap: 6px;">
              ${pt.type === 'origin' ? '🔴 ORIGIN THREAT NODE' : pt.type === 'target' ? '🟢 TARGET INBOX MX' : '🟡 MTA RELAY HOP'}
            </div>
            <div style="font-family: monospace; font-size: 12px; font-weight: 700; background: #f1f5f9; padding: 4px 6px; border-radius: 4px; margin-bottom: 6px;">
              ${pt.ip || 'Unknown IP'}
            </div>
            <div style="display: grid; grid-template-columns: 70px 1fr; gap: 4px; line-height: 1.4; margin-bottom: 8px;">
              <span style="color: #64748b;">Location:</span>
              <span style="font-weight: 600;">${pt.city || 'Unknown'}, ${pt.country || 'Unknown'}</span>
              <span style="color: #64748b;">ISP / ASN:</span>
              <span style="font-size: 11px;">${pt.isp || pt.asn || 'Resolved via BGP'}</span>
              <span style="color: #64748b;">Coords:</span>
              <span style="font-family: monospace; font-size: 11px;">${pt.lat.toFixed(4)}, ${pt.lon.toFixed(4)}</span>
            </div>
            <div style="display: flex; gap: 6px; margin-top: 6px; padding-top: 6px; border-top: 1px solid #e2e8f0;">
              <a href="${googleMapsUrl}" target="_blank" rel="noopener noreferrer" style="
                flex: 1;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 4px;
                background: #0284c7;
                color: #ffffff;
                text-decoration: none;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 700;
              ">
                📍 Open Google Maps ↗
              </a>
            </div>
          </div>
        `;

        marker.bindPopup(popupContent, { maxWidth: 280 });
        marker.on('click', () => setSelectedHop(pt));
        markersRef.current.push(marker);
        latlngs.push([pt.lat, pt.lon]);
      });

      // Draw dashed trajectory connecting hops
      if (latlngs.length > 1) {
        polylineRef.current = L.polyline(latlngs, {
          color: '#ef4444',
          weight: 2.5,
          opacity: 0.85,
          dashArray: '6, 8',
          lineCap: 'round',
        }).addTo(map);

        map.fitBounds(L.latLngBounds(latlngs), { padding: [50, 50], maxZoom: 8 });
      } else if (latlngs.length === 1) {
        map.setView(latlngs[0], 6);
      }
    }

    // Fix render size if container resized
    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 150);

    return () => clearTimeout(timer);
  }, [activeLayer, points.length, originGeo]);

  // Clean up Leaflet on unmount
  useEffect(() => {
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  const handleFitBounds = () => {
    if (!mapInstanceRef.current || points.length === 0) return;
    const latlngs = points.map((p) => [p.lat, p.lon]);
    if (latlngs.length > 1) {
      mapInstanceRef.current.fitBounds(L.latLngBounds(latlngs), { padding: [40, 40] });
    } else {
      mapInstanceRef.current.setView(latlngs[0], 6);
    }
  };

  const handleFocusOrigin = () => {
    if (!mapInstanceRef.current || !primaryPoint) return;
    mapInstanceRef.current.setView([primaryPoint.lat, primaryPoint.lon], 9, {
      animate: true,
      duration: 1.2,
    });
  };

  const handleCopyCoords = () => {
    if (!primaryPoint) return;
    const text = `${primaryPoint.lat.toFixed(6)}, ${primaryPoint.lon.toFixed(6)}`;
    navigator.clipboard?.writeText(text);
    setCopiedCoords(true);
    setTimeout(() => setCopiedCoords(false), 2000);
  };

  const saveGoogleKey = (key) => {
    setGoogleKey(key);
    localStorage.setItem('CYBERTRACE_GOOGLE_MAPS_KEY', key);
    setShowKeyModal(false);
  };

  // Google Maps Embed URL
  const googleEmbedUrl = googleKey
    ? `https://www.google.com/maps/embed/v1/place?key=${googleKey}&q=${primaryPoint.lat},${primaryPoint.lon}&zoom=11`
    : `https://maps.google.com/maps?q=${primaryPoint.lat},${primaryPoint.lon}&t=k&z=11&ie=UTF8&iwloc=&output=embed`;

  return (
    <div
      className="panel fade-in"
      style={{
        background: '#ffffff',
        border: '1px solid #cbd5e1',
        borderRadius: 'var(--radius-sm)',
        overflow: 'hidden',
        boxShadow: '0 1px 4px rgba(15, 23, 42, 0.04)',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Map Header & Forensics Control Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 10,
          padding: '12px 16px',
          background: '#f8fafc',
          borderBottom: '1px solid #e2e8f0',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 16 }}>🗺️</span>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#0284c7', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
              GEOGRAPHIC ATTRIBUTION ENGINE
            </div>
            <h3 style={{ fontSize: 15, fontWeight: 800, color: '#0f172a', margin: 0 }}>
              {title}
            </h3>
          </div>
        </div>

        {/* Controls: Layer Toggles & Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {/* Map Layer Segmented Control */}
          <div
            style={{
              display: 'inline-flex',
              background: '#e2e8f0',
              padding: 2,
              borderRadius: 6,
              fontSize: 11,
              fontWeight: 700,
            }}
          >
            <button
              onClick={() => setActiveLayer('dark')}
              style={{
                background: activeLayer === 'dark' ? '#0f172a' : 'transparent',
                color: activeLayer === 'dark' ? '#38bdf8' : '#64748b',
                border: 'none',
                padding: '4px 8px',
                borderRadius: 4,
                cursor: 'pointer',
              }}
            >
              Dark Radar
            </button>
            <button
              onClick={() => setActiveLayer('osm')}
              style={{
                background: activeLayer === 'osm' ? '#0f172a' : 'transparent',
                color: activeLayer === 'osm' ? '#38bdf8' : '#64748b',
                border: 'none',
                padding: '4px 8px',
                borderRadius: 4,
                cursor: 'pointer',
              }}
            >
              Street OSM
            </button>
            <button
              onClick={() => setActiveLayer('google')}
              style={{
                background: activeLayer === 'google' ? '#0284c7' : 'transparent',
                color: activeLayer === 'google' ? '#ffffff' : '#64748b',
                border: 'none',
                padding: '4px 8px',
                borderRadius: 4,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
              }}
            >
              <span>🛰️ Google Maps</span>
            </button>
          </div>

          {/* Recenter / Focus Controls */}
          {activeLayer !== 'google' && (
            <>
              <button
                onClick={handleFitBounds}
                title="Fit all relay hops on map"
                style={{
                  background: '#ffffff',
                  border: '1px solid #cbd5e1',
                  borderRadius: 6,
                  padding: '4px 8px',
                  fontSize: 11,
                  fontWeight: 700,
                  color: '#334155',
                  cursor: 'pointer',
                }}
              >
                Fit All
              </button>
              <button
                onClick={handleFocusOrigin}
                title="Zoom into Threat Origin"
                style={{
                  background: '#fef2f2',
                  border: '1px solid #fecaca',
                  borderRadius: 6,
                  padding: '4px 8px',
                  fontSize: 11,
                  fontWeight: 700,
                  color: '#dc2626',
                  cursor: 'pointer',
                }}
              >
                Focus Origin
              </button>
            </>
          )}

          {/* External Google Maps Button */}
          <a
            href={`https://www.google.com/maps?q=${primaryPoint.lat},${primaryPoint.lon}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              background: '#f0f9ff',
              border: '1px solid #bae6fd',
              color: '#0284c7',
              textDecoration: 'none',
              padding: '4px 8px',
              borderRadius: 6,
              fontSize: 11,
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            Google Maps ↗
          </a>

          <button
            onClick={() => setShowKeyModal(true)}
            title="Configure Google Maps API Key"
            style={{
              background: '#ffffff',
              border: '1px solid #cbd5e1',
              borderRadius: 6,
              padding: '4px 6px',
              fontSize: 11,
              cursor: 'pointer',
              color: '#64748b',
            }}
          >
            ⚙️ Key
          </button>
        </div>
      </div>

      {/* Main Map Canvas Area */}
      <div style={{ position: 'relative', height, width: '100%', background: '#090d16' }}>
        {activeLayer === 'google' ? (
          /* Google Maps View (Satellite Embed) */
          <div style={{ width: '100%', height: '100%', position: 'relative' }}>
            <iframe
              title="Google Maps Satellite Forensic View"
              src={googleEmbedUrl}
              style={{
                width: '100%',
                height: '100%',
                border: 'none',
                filter: 'contrast(1.05)',
              }}
              allowFullScreen=""
              loading="lazy"
            />
            {/* Overlay Bar */}
            <div
              style={{
                position: 'absolute',
                top: 10,
                left: 10,
                background: 'rgba(15, 23, 42, 0.88)',
                color: '#ffffff',
                padding: '6px 12px',
                borderRadius: 6,
                fontSize: 11,
                fontFamily: 'monospace',
                backdropFilter: 'blur(4px)',
                boxShadow: '0 2px 10px rgba(0,0,0,0.5)',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <span style={{ color: '#ef4444' }}>●</span> Google Maps Live Satellite & Terrain View
            </div>
          </div>
        ) : (
          /* Leaflet Forensic Interactive Map */
          <div
            ref={mapContainerRef}
            style={{
              width: '100%',
              height: '100%',
              zIndex: 1,
            }}
          />
        )}

        {/* Tactical Coordinate Telemetry Badge */}
        <div
          style={{
            position: 'absolute',
            bottom: 10,
            left: 10,
            zIndex: 1000,
            background: 'rgba(15, 23, 42, 0.88)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            borderRadius: 6,
            padding: '6px 10px',
            color: '#f8fafc',
            fontFamily: 'monospace',
            fontSize: 11,
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            gap: 12,
          }}
        >
          <div>
            <span style={{ color: '#38bdf8', fontWeight: 700 }}>ORIGIN:</span>{' '}
            {primaryPoint.city}, {primaryPoint.country}
          </div>
          <div style={{ color: '#94a3b8' }}>|</div>
          <div>
            {primaryPoint.lat.toFixed(4)}°, {primaryPoint.lon.toFixed(4)}°
          </div>
          <button
            onClick={handleCopyCoords}
            style={{
              background: copiedCoords ? '#16a34a' : 'rgba(56, 189, 248, 0.2)',
              border: 'none',
              borderRadius: 4,
              color: '#ffffff',
              fontSize: 10,
              padding: '2px 6px',
              cursor: 'pointer',
              fontWeight: 700,
            }}
          >
            {copiedCoords ? 'COPIED!' : 'COPY GPS'}
          </button>
        </div>
      </div>

      {/* Hop Chain Strip Below Map */}
      {points.length > 0 && (
        <div
          style={{
            padding: '10px 16px',
            background: '#f8fafc',
            borderTop: '1px solid #e2e8f0',
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            overflowX: 'auto',
          }}
        >
          <span style={{ fontSize: 10, fontWeight: 800, color: '#64748b', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
            TRANSMISSION PATH ({points.length} LOCATIONS):
          </span>
          {points.map((pt, idx) => (
            <div
              key={idx}
              onClick={() => {
                setSelectedHop(pt);
                if (mapInstanceRef.current) {
                  mapInstanceRef.current.setView([pt.lat, pt.lon], 7, { animate: true });
                }
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '4px 8px',
                background: pt.type === 'origin' ? '#fef2f2' : pt.type === 'target' ? '#f0fdf4' : '#ffffff',
                border: `1px solid ${pt.type === 'origin' ? '#fca5a5' : pt.type === 'target' ? '#bbf7d0' : '#cbd5e1'}`,
                borderRadius: 4,
                cursor: 'pointer',
                fontSize: 11,
                whiteSpace: 'nowrap',
              }}
            >
              <span>{pt.type === 'origin' ? '🔴' : pt.type === 'target' ? '🟢' : '🟡'}</span>
              <span className="mono" style={{ fontWeight: 700, color: '#0f172a' }}>
                {pt.ip}
              </span>
              <span style={{ color: '#64748b', fontSize: 10 }}>({pt.city || pt.country})</span>
            </div>
          ))}
        </div>
      )}

      {/* Modal to configure Google Maps API Key */}
      {showKeyModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.6)',
            backdropFilter: 'blur(3px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
          }}
        >
          <div
            style={{
              background: '#ffffff',
              borderRadius: 8,
              padding: 24,
              width: '90%',
              maxWidth: 480,
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)',
            }}
          >
            <h3 style={{ margin: '0 0 8px 0', fontSize: 16, fontWeight: 800, color: '#0f172a' }}>
              Google Maps Platform Configuration
            </h3>
            <p style={{ margin: '0 0 16px 0', fontSize: 12, color: '#64748b', lineHeight: 1.5 }}>
              Enter an authorized Google Maps Platform API key to enable premium high-resolution Google Maps Satellite and Street View within the forensic analysis workstation. (If blank, standard public map embed is used).
            </p>
            <input
              type="text"
              defaultValue={googleKey}
              id="google-maps-key-input"
              placeholder="AIzaSy..."
              className="mono"
              style={{
                width: '100%',
                padding: '8px 12px',
                fontSize: 12,
                border: '1px solid #cbd5e1',
                borderRadius: 6,
                marginBottom: 16,
                boxSizing: 'border-box',
              }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                onClick={() => setShowKeyModal(false)}
                style={{
                  background: '#f1f5f9',
                  border: '1px solid #cbd5e1',
                  borderRadius: 6,
                  padding: '6px 14px',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  const input = document.getElementById('google-maps-key-input');
                  saveGoogleKey(input?.value?.trim() || '');
                }}
                style={{
                  background: '#0284c7',
                  border: 'none',
                  borderRadius: 6,
                  color: '#ffffff',
                  padding: '6px 16px',
                  fontSize: 12,
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                Save Key
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
