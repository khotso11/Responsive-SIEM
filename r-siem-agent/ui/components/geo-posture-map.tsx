"use client";

import { useEffect, useMemo, useState } from "react";
import { EndpointGeoSummary } from "@/lib/types";

type SiteAggregate = {
  lat: number;
  lon: number;
  label?: string;
};

type GeoPostureMapProps = {
  endpoints: EndpointGeoSummary[];
  generatedAt?: string;
  onSelectEndpoint?: (nodeID: string) => void;
  probeHover?: boolean;
  useSiteAggregateForUnlocated?: boolean;
  siteAggregate?: SiteAggregate | null;
};

type GeoFeature = {
  geometry?: {
    type?: string;
    coordinates?: unknown;
  };
};

type MapView = {
  zoom: number;
  centerX: number;
  centerY: number;
};

type Marker = {
  endpoint: EndpointGeoSummary;
  x: number;
  y: number;
  radius: number;
  color: string;
};

const MAP_W = 1060;
const MAP_H = 520;
const LESOTHO_CENTER = { lat: -29.31, lon: 27.48 };

function isValidLatLon(lat: unknown, lon: unknown): lat is number {
  if (typeof lat !== "number" || typeof lon !== "number") return false;
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false;
  return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

function statusRank(status: string): number {
  const s = status.toLowerCase();
  if (s === "critical") return 4;
  if (s === "warning") return 3;
  if (s === "unknown") return 2;
  return 1;
}

function statusColor(status: string): string {
  const s = status.toLowerCase();
  if (s === "active") return "#22C55E";
  if (s === "warning") return "#F59E0B";
  if (s === "critical") return "#EF4444";
  return "#64748B";
}

function statusBadgeClass(status: string): string {
  const s = status.toLowerCase();
  if (s === "active") return "badge-good";
  if (s === "warning") return "badge-warn";
  if (s === "critical") return "badge-bad";
  return "badge-info";
}

function toMercator(lon: number, lat: number): { x: number; y: number } {
  const clampedLat = Math.max(-85, Math.min(85, lat));
  const lambda = (lon * Math.PI) / 180;
  const phi = (clampedLat * Math.PI) / 180;
  const x = ((lambda + Math.PI) / (2 * Math.PI)) * MAP_W;
  const mercN = Math.log(Math.tan(Math.PI / 4 + phi / 2));
  const y = MAP_H / 2 - (MAP_W / (2 * Math.PI)) * mercN;
  return { x, y };
}

function projectMercator(x: number, y: number, view: MapView): { x: number; y: number } {
  return {
    x: (x - view.centerX) * view.zoom + MAP_W / 2,
    y: (y - view.centerY) * view.zoom + MAP_H / 2
  };
}

function project(lon: number, lat: number, view: MapView): { x: number; y: number } {
  const m = toMercator(lon, lat);
  return projectMercator(m.x, m.y, view);
}

function geoPathFromCoordinates(coords: unknown, view: MapView): string {
  if (!Array.isArray(coords)) return "";
  const rings = coords as unknown[];
  let d = "";
  for (const ringAny of rings) {
    if (!Array.isArray(ringAny)) continue;
    const ring = ringAny as unknown[];
    let first = true;
    for (const pointAny of ring) {
      if (!Array.isArray(pointAny) || pointAny.length < 2) continue;
      const lon = Number(pointAny[0]);
      const lat = Number(pointAny[1]);
      if (!Number.isFinite(lon) || !Number.isFinite(lat)) continue;
      const p = project(lon, lat, view);
      d += `${first ? "M" : "L"}${p.x.toFixed(2)} ${p.y.toFixed(2)} `;
      first = false;
    }
    if (!first) d += "Z ";
  }
  return d.trim();
}

function buildFeaturePath(feature: GeoFeature, view: MapView): string {
  const geom = feature.geometry;
  if (!geom || !geom.type || !geom.coordinates) return "";
  if (geom.type === "Polygon") {
    return geoPathFromCoordinates(geom.coordinates, view);
  }
  if (geom.type === "MultiPolygon" && Array.isArray(geom.coordinates)) {
    return (geom.coordinates as unknown[])
      .map((poly) => geoPathFromCoordinates(poly, view))
      .filter(Boolean)
      .join(" ");
  }
  return "";
}

function normalizeGeoSource(source: string | undefined): string {
  return (source || "").trim().toLowerCase();
}

function isLocatedEndpoint(ep: EndpointGeoSummary): boolean {
  const src = normalizeGeoSource(ep.geo?.source);
  if (!(src === "configured" || src === "manual" || src === "explicit")) {
    return false;
  }
  return isValidLatLon(ep.geo?.lat, ep.geo?.lon);
}

function markerRadius(events1h: number): number {
  return Math.min(16, 4 + Math.sqrt(Math.max(0, events1h) + 1) / 2.4);
}

export function GeoPostureMap({
  endpoints,
  generatedAt,
  onSelectEndpoint,
  probeHover = false,
  useSiteAggregateForUnlocated = false,
  siteAggregate = null
}: GeoPostureMapProps) {
  const [features, setFeatures] = useState<GeoFeature[]>([]);
  const [zoomOverride, setZoomOverride] = useState<number | null>(null);
  const [selectedNode, setSelectedNode] = useState("");
  const [hoveredMarker, setHoveredMarker] = useState<Marker | null>(null);
  const [hoveredSite, setHoveredSite] = useState(false);
  const [hoverPos, setHoverPos] = useState({ x: MAP_W / 2, y: MAP_H / 2 });

  useEffect(() => {
    let done = false;
    fetch("/maps/world-countries.geojson", { cache: "force-cache" })
      .then((res) => res.json())
      .then((json) => {
        if (done) return;
        const feats = Array.isArray(json?.features) ? (json.features as GeoFeature[]) : [];
        setFeatures(feats);
      })
      .catch(() => {
        if (!done) setFeatures([]);
      });
    return () => {
      done = true;
    };
  }, []);

  const locatedEndpoints = useMemo(() => {
    return (endpoints || []).filter(isLocatedEndpoint);
  }, [endpoints]);

  const unlocatedEndpoints = useMemo(() => {
    return (endpoints || []).filter((ep) => !isLocatedEndpoint(ep));
  }, [endpoints]);

  const siteAggregateEnabled = useMemo(() => {
    return (
      Boolean(useSiteAggregateForUnlocated) &&
      Boolean(siteAggregate) &&
      isValidLatLon(siteAggregate?.lat, siteAggregate?.lon) &&
      unlocatedEndpoints.length > 0
    );
  }, [siteAggregate, unlocatedEndpoints.length, useSiteAggregateForUnlocated]);

  const fitMercatorPoints = useMemo(() => {
    const points = locatedEndpoints
      .map((ep) => {
        if (!isValidLatLon(ep.geo?.lat, ep.geo?.lon)) return null;
        return toMercator(ep.geo.lon, ep.geo.lat);
      })
      .filter((p): p is { x: number; y: number } => p !== null);
    if (siteAggregateEnabled && siteAggregate && isValidLatLon(siteAggregate.lat, siteAggregate.lon)) {
      points.push(toMercator(siteAggregate.lon, siteAggregate.lat));
    }
    return points;
  }, [locatedEndpoints, siteAggregate, siteAggregateEnabled]);

  const autoView = useMemo<MapView>(() => {
    if (fitMercatorPoints.length === 0) {
      const c = toMercator(LESOTHO_CENTER.lon, LESOTHO_CENTER.lat);
      return { zoom: 2.2, centerX: c.x, centerY: c.y };
    }
    const minX = Math.min(...fitMercatorPoints.map((p) => p.x));
    const maxX = Math.max(...fitMercatorPoints.map((p) => p.x));
    const minY = Math.min(...fitMercatorPoints.map((p) => p.y));
    const maxY = Math.max(...fitMercatorPoints.map((p) => p.y));
    const dx = Math.max(24, maxX - minX);
    const dy = Math.max(24, maxY - minY);
    const pad = 72;
    const zx = (MAP_W - pad * 2) / dx;
    const zy = (MAP_H - pad * 2) / dy;
    const zoom = Math.max(1, Math.min(4, Math.min(zx, zy)));
    return {
      zoom,
      centerX: (minX + maxX) / 2,
      centerY: (minY + maxY) / 2
    };
  }, [fitMercatorPoints]);

  const zoom = zoomOverride ?? autoView.zoom;
  const view = useMemo<MapView>(() => ({ zoom, centerX: autoView.centerX, centerY: autoView.centerY }), [autoView.centerX, autoView.centerY, zoom]);

  useEffect(() => {
    setZoomOverride(null);
  }, [autoView.centerX, autoView.centerY, locatedEndpoints.length, siteAggregateEnabled]);

  const landPaths = useMemo(() => {
    return features.map((f) => buildFeaturePath(f, view)).filter(Boolean);
  }, [features, view]);

  const markers = useMemo<Marker[]>(() => {
    return locatedEndpoints
      .map((ep) => {
        if (!isValidLatLon(ep.geo?.lat, ep.geo?.lon)) return null;
        const p = project(ep.geo.lon, ep.geo.lat, view);
        return {
          endpoint: ep,
          x: p.x,
          y: p.y,
          radius: markerRadius(ep.events_1h || 0),
          color: statusColor(ep.status || "unknown")
        };
      })
      .filter((m): m is Marker => m !== null)
      .sort((a, b) => {
        const r = statusRank(b.endpoint.status || "unknown") - statusRank(a.endpoint.status || "unknown");
        if (r !== 0) return r;
        return a.endpoint.node_id.localeCompare(b.endpoint.node_id);
      });
  }, [locatedEndpoints, view]);

  const siteMarker = useMemo(() => {
    if (!siteAggregateEnabled || !siteAggregate || !isValidLatLon(siteAggregate.lat, siteAggregate.lon)) return null;
    const p = project(siteAggregate.lon, siteAggregate.lat, view);
    return {
      x: p.x,
      y: p.y,
      label: siteAggregate.label || "Site aggregate (unlocated)"
    };
  }, [siteAggregate, siteAggregateEnabled, view]);

  useEffect(() => {
    if (probeHover && !hoveredMarker && markers.length > 0) {
      setHoveredMarker(markers[0]);
      setHoverPos({ x: markers[0].x, y: markers[0].y });
    }
  }, [hoveredMarker, markers, probeHover]);

  const selectedEndpoint = useMemo(() => {
    if (!selectedNode) return null;
    return endpoints.find((ep) => ep.node_id === selectedNode) || null;
  }, [endpoints, selectedNode]);

  const tooltipStyle = useMemo(() => {
    const left = Math.max(2, Math.min(82, (hoverPos.x / MAP_W) * 100));
    const top = Math.max(4, Math.min(76, (hoverPos.y / MAP_H) * 100));
    return { left: `${left}%`, top: `${top}%` };
  }, [hoverPos.x, hoverPos.y]);

  const tooltipVisible = Boolean(hoveredMarker || hoveredSite);

  return (
    <div
      className="relative h-full min-h-[540px] bg-[radial-gradient(circle_at_20%_8%,rgba(34,211,238,0.08),transparent_40%),linear-gradient(180deg,#070B14_0%,#0B1630_100%)]"
      data-geo-honest-mode="1"
      data-located-count={locatedEndpoints.length}
      data-unlocated-count={unlocatedEndpoints.length}
    >
      <div className="absolute right-3 top-3 z-20 flex items-center gap-2">
        <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setZoomOverride((z) => Math.max(1, Number(((z ?? autoView.zoom) - 0.25).toFixed(2))))}>
          -
        </button>
        <span className="rounded border border-ink-700 px-2 py-1 text-xs">zoom {zoom.toFixed(2)}x</span>
        <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setZoomOverride((z) => Math.min(4, Number(((z ?? autoView.zoom) + 0.25).toFixed(2))))}>
          +
        </button>
        <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setZoomOverride(null)}>
          Reset view
        </button>
      </div>

      <svg
        viewBox={`0 0 ${MAP_W} ${MAP_H}`}
        className="h-full min-h-[540px] w-full"
        data-geo-basemap={landPaths.length > 0 ? "ready" : "loading"}
      >
        <defs>
          <radialGradient id="rsiemMapAura" cx="50%" cy="50%" r="65%">
            <stop offset="0%" stopColor="rgba(34,211,238,0.10)" />
            <stop offset="100%" stopColor="rgba(7,11,20,0)" />
          </radialGradient>
        </defs>

        <rect x="0" y="0" width={MAP_W} height={MAP_H} fill="#070B14" />
        <rect x="0" y="0" width={MAP_W} height={MAP_H} fill="url(#rsiemMapAura)" />

        {landPaths.map((d, i) => (
          <path key={`land-${i}`} d={d} data-geo-land="1" fill="#18243D" stroke="rgba(255,255,255,0.09)" strokeWidth="0.8" />
        ))}

        {markers.map((marker) => {
          const focused = selectedNode !== "" && marker.endpoint.node_id === selectedNode;
          return (
            <g
              key={marker.endpoint.node_id}
              transform={`translate(${marker.x.toFixed(2)},${marker.y.toFixed(2)})`}
              data-geo-marker="1"
              data-marker-kind="endpoint"
              data-node-id={marker.endpoint.node_id}
              role="button"
              tabIndex={0}
              className="cursor-pointer outline-none"
              onMouseEnter={() => {
                setHoveredSite(false);
                setHoveredMarker(marker);
                setHoverPos({ x: marker.x, y: marker.y });
              }}
              onMouseLeave={() => setHoveredMarker(null)}
              onFocus={() => {
                setHoveredSite(false);
                setHoveredMarker(marker);
                setHoverPos({ x: marker.x, y: marker.y });
              }}
              onBlur={() => setHoveredMarker(null)}
              onClick={() => {
                setSelectedNode(marker.endpoint.node_id);
                if (onSelectEndpoint) onSelectEndpoint(marker.endpoint.node_id);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setSelectedNode(marker.endpoint.node_id);
                  if (onSelectEndpoint) onSelectEndpoint(marker.endpoint.node_id);
                }
              }}
            >
              <circle r={marker.radius + (focused ? 7 : 5)} fill={marker.color} opacity={focused ? 0.30 : 0.22} />
              <circle r={marker.radius + (focused ? 3 : 2)} fill={marker.color} opacity={0.35} />
              <circle r={marker.radius} fill={marker.color} opacity={0.92} />
            </g>
          );
        })}

        {siteMarker ? (
          <g
            transform={`translate(${siteMarker.x.toFixed(2)},${siteMarker.y.toFixed(2)})`}
            data-geo-marker="1"
            data-marker-kind="site-aggregate"
            role="button"
            tabIndex={0}
            className="cursor-pointer outline-none"
            onMouseEnter={() => {
              setHoveredMarker(null);
              setHoveredSite(true);
              setHoverPos({ x: siteMarker.x, y: siteMarker.y });
            }}
            onMouseLeave={() => setHoveredSite(false)}
            onFocus={() => {
              setHoveredMarker(null);
              setHoveredSite(true);
              setHoverPos({ x: siteMarker.x, y: siteMarker.y });
            }}
            onBlur={() => setHoveredSite(false)}
          >
            <circle r={14} fill="#64748B" opacity={0.28} />
            <circle r={10} fill="#64748B" opacity={0.72} />
            <text y="3.6" textAnchor="middle" fontSize="10" fill="#071019" fontWeight="700">
              {unlocatedEndpoints.length}
            </text>
          </g>
        ) : null}
      </svg>

      {locatedEndpoints.length === 0 ? (
        <div
          className="pointer-events-none absolute left-1/2 top-1/2 z-20 w-[92%] max-w-2xl -translate-x-1/2 -translate-y-1/2 rounded-lg border border-ink-700 bg-[#0B1324]/92 px-4 py-3 text-center text-sm text-ink-100"
          data-geo-empty-overlay="1"
        >
          No endpoint geolocation configured. Showing 0 located endpoints; {unlocatedEndpoints.length} unlocated.
        </div>
      ) : null}

      <div
        className="pointer-events-none absolute z-20 w-80 rounded-lg border border-ink-700 bg-[#0B1324]/95 p-3 text-xs shadow-panel"
        data-geo-tooltip="1"
        data-visible={tooltipVisible ? "1" : "0"}
        style={tooltipStyle}
      >
        {hoveredMarker ? (
          <>
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="font-semibold text-ink-100">{hoveredMarker.endpoint.node_id}</span>
              <span className={statusBadgeClass(hoveredMarker.endpoint.status)}>{hoveredMarker.endpoint.status.toUpperCase()}</span>
            </div>
            <div className="text-ink-300">last_seen: {hoveredMarker.endpoint.last_seen_rfc3339 || "-"}</div>
            <div className="text-ink-300">events_5m / events_1h: {hoveredMarker.endpoint.events_5m || 0} / {hoveredMarker.endpoint.events_1h || 0}</div>
            <div className="text-ink-300">
              sources:{" "}
              {Object.entries(hoveredMarker.endpoint.source_dist || {})
                .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
                .slice(0, 2)
                .map(([k, v]) => `${k}:${v}`)
                .join(", ") || "-"}
            </div>
          </>
        ) : hoveredSite && siteMarker ? (
          <>
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="font-semibold text-ink-100">{siteMarker.label}</span>
              <span className="badge-info">AGGREGATE</span>
            </div>
            <div className="text-ink-300">Unlocated endpoints: {unlocatedEndpoints.length}</div>
            <div className="text-ink-300">Demo mode only. Real endpoint geolocation not configured.</div>
          </>
        ) : (
          <div className="text-ink-400">Hover endpoint marker for details</div>
        )}
      </div>

      {selectedEndpoint ? (
        <div className="absolute bottom-11 right-3 z-20 w-80 rounded-lg border border-ink-700 bg-[#0B1324]/95 p-3 text-xs shadow-panel">
          <div className="mb-1 text-[11px] uppercase tracking-[0.08em] text-ink-400">Selected endpoint</div>
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="font-semibold text-ink-100">{selectedEndpoint.node_id}</span>
            <span className={statusBadgeClass(selectedEndpoint.status)}>{selectedEndpoint.status.toUpperCase()}</span>
          </div>
          <div className="text-ink-300">last_seen: {selectedEndpoint.last_seen_rfc3339 || "-"}</div>
          <div className="text-ink-300">events_5m / events_1h: {selectedEndpoint.events_5m} / {selectedEndpoint.events_1h}</div>
        </div>
      ) : null}

      <div className="absolute bottom-2 left-2 right-2 z-20 flex flex-wrap items-center justify-between gap-2 rounded border border-ink-700/80 bg-[#0B1324]/85 px-3 py-2 text-[11px]">
        <div className="flex flex-wrap items-center gap-3 text-ink-200">
          <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "#22C55E" }} />OK</span>
          <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "#F59E0B" }} />Warn</span>
          <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "#EF4444" }} />Critical</span>
          <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "#64748B" }} />Unknown</span>
        </div>
        <span className="text-ink-300">Last refresh: {generatedAt || "-"}</span>
      </div>
    </div>
  );
}
