import React, { useState } from 'react';
import { 
  Network, 
  Server, 
  Globe, 
  User, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Info,
  CheckCircle2,
  XCircle,
  HelpCircle
} from 'lucide-react';
import { UserHostGraph, GraphNode, GraphEdge, UserIncident } from '../types';

interface UserHostGraphVisualizerProps {
  graph?: UserHostGraph;
  incident: UserIncident;
}

export const UserHostGraphVisualizer: React.FC<UserHostGraphVisualizerProps> = ({
  graph,
  incident
}) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="detail-card">
        <div className="detail-card-title">
          <Network size={15} />
          User-to-Host Communication Graph
        </div>
        <div style={{ fontSize: 12, color: 'var(--slate-500)', fontStyle: 'italic', padding: '16px 0' }}>
          No host communication telemetry recorded for this incident.
        </div>
      </div>
    );
  }

  const userNode = graph.nodes.find(n => n.type === 'USER');
  const ipNodes = graph.nodes.filter(n => n.type === 'IP');
  const hostNodes = graph.nodes.filter(n => n.type === 'HOST');

  const selectedNode = graph.nodes.find(n => n.id === selectedNodeId) || null;

  // Layout coordinates for SVG
  const svgWidth = 820;
  const svgHeight = Math.max(280, Math.max(ipNodes.length, hostNodes.length) * 75 + 60);

  const userX = 90;
  const userY = svgHeight / 2;

  const ipX = 340;
  const hostX = 640;

  // Calculate Y coordinates for IPs
  const ipSpacing = svgHeight / (ipNodes.length + 1);
  const ipPositions = new Map<string, { x: number; y: number }>();
  ipNodes.forEach((node, i) => {
    ipPositions.set(node.id, { x: ipX, y: (i + 1) * ipSpacing });
  });

  // Calculate Y coordinates for Hosts
  const hostSpacing = svgHeight / (hostNodes.length + 1);
  const hostPositions = new Map<string, { x: number; y: number }>();
  hostNodes.forEach((node, i) => {
    hostPositions.set(node.id, { x: hostX, y: (i + 1) * hostSpacing });
  });

  return (
    <div className="detail-card">
      <div className="detail-card-title" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Network size={15} />
          <span>User-to-Host Communication &amp; Lateral Movement Graph</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
          <span 
            className="badge" 
            style={{ 
              backgroundColor: graph.novelHostsCount > 0 ? '#fef2f2' : '#f0fdf4',
              color: graph.novelHostsCount > 0 ? '#991b1b' : '#166534',
              border: `1px solid ${graph.novelHostsCount > 0 ? '#fecaca' : '#bbf7d0'}`
            }}
          >
            {graph.novelHostsCount} Novel Host{graph.novelHostsCount !== 1 ? 's' : ''} (Lateral Expansion)
          </span>
          <span className="badge" style={{ backgroundColor: '#f1f5f9', color: '#334155', border: '1px solid #cbd5e1' }}>
            {graph.baselineHostsCount} Habitual Baseline Host{graph.baselineHostsCount !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      <div style={{ fontSize: 11, color: 'var(--slate-600)', marginBottom: 12 }}>
        Visual topological mapping of account authentication paths from origin IPs to target endpoints. Identifies habitual access vs novel lateral expansion.
      </div>

      {/* SVG Canvas Container */}
      <div 
        style={{ 
          border: '1px solid #e2e8f0', 
          borderRadius: 6, 
          backgroundColor: '#fafbfc', 
          overflowX: 'auto',
          position: 'relative'
        }}
      >
        <svg width={svgWidth} height={svgHeight} style={{ display: 'block', margin: '0 auto' }}>
          <defs>
            {/* Arrow markers */}
            <marker id="arrow-green" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#16a34a" />
            </marker>
            <marker id="arrow-red" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#dc2626" />
            </marker>
            <marker id="arrow-amber" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#d97706" />
            </marker>
          </defs>

          {/* Column Background Header Bands */}
          <text x={userX} y={22} textAnchor="middle" fill="#64748b" fontSize="10" fontWeight="700" letterSpacing="0.5">
            USER ACCOUNT
          </text>
          <text x={ipX} y={22} textAnchor="middle" fill="#64748b" fontSize="10" fontWeight="700" letterSpacing="0.5">
            ORIGIN IP / GATEWAY
          </text>
          <text x={hostX} y={22} textAnchor="middle" fill="#64748b" fontSize="10" fontWeight="700" letterSpacing="0.5">
            TARGET HOST / SERVER
          </text>

          {/* Draw Edges */}
          {graph.edges.map(edge => {
            let startPos = { x: 0, y: 0 };
            let endPos = { x: 0, y: 0 };

            if (edge.source.startsWith('user:')) {
              startPos = { x: userX, y: userY };
              endPos = ipPositions.get(edge.target) || { x: ipX, y: userY };
            } else if (edge.source.startsWith('ip:')) {
              startPos = ipPositions.get(edge.source) || { x: ipX, y: userY };
              endPos = hostPositions.get(edge.target) || { x: hostX, y: userY };
            }

            const isSelected = selectedNodeId && (edge.source === selectedNodeId || edge.target === selectedNodeId);
            const edgeColor = edge.action === 'SUCCESS' ? '#16a34a' : edge.action === 'FAILURE' ? '#dc2626' : '#d97706';
            const markerType = edge.action === 'SUCCESS' ? 'url(#arrow-green)' : edge.action === 'FAILURE' ? 'url(#arrow-red)' : 'url(#arrow-amber)';

            // Cubic Bezier curve for smooth flow
            const midX = (startPos.x + endPos.x) / 2;
            const pathD = `M ${startPos.x} ${startPos.y} C ${midX} ${startPos.y}, ${midX} ${endPos.y}, ${endPos.x} ${endPos.y}`;

            return (
              <g key={edge.id}>
                <path
                  d={pathD}
                  fill="none"
                  stroke={edgeColor}
                  strokeWidth={isSelected ? 3 : edge.isNovelPath ? 2.5 : 1.8}
                  strokeDasharray={edge.isNovelPath ? '5,4' : undefined}
                  markerEnd={markerType}
                  opacity={selectedNodeId && !isSelected ? 0.25 : 0.85}
                  style={{ transition: 'all 0.2s ease' }}
                />
              </g>
            );
          })}

          {/* User Node */}
          {userNode && (
            <g 
              transform={`translate(${userX}, ${userY})`}
              onClick={() => setSelectedNodeId(selectedNodeId === userNode.id ? null : userNode.id)}
              style={{ cursor: 'pointer' }}
            >
              <circle
                r={26}
                fill="#ffffff"
                stroke={selectedNodeId === userNode.id ? '#0284c7' : '#334155'}
                strokeWidth={selectedNodeId === userNode.id ? 3 : 2}
                filter="drop-shadow(0 2px 3px rgba(0,0,0,0.1))"
              />
              <circle r={20} fill="#f1f5f9" />
              <text y={4} textAnchor="middle" fill="#1e293b" fontSize="12" fontWeight="700">
                👤
              </text>
              <text y={40} textAnchor="middle" fill="#0f172a" fontSize="11" fontWeight="700">
                {userNode.label}
              </text>
              <text y={52} textAnchor="middle" fill="#64748b" fontSize="9">
                {incident.accountRole || 'REGULAR_USER'}
              </text>
            </g>
          )}

          {/* IP Nodes */}
          {ipNodes.map(node => {
            const pos = ipPositions.get(node.id) || { x: ipX, y: 0 };
            const isSelected = selectedNodeId === node.id;
            const isVpn = node.isVpn;

            return (
              <g 
                key={node.id} 
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNodeId(selectedNodeId === node.id ? null : node.id)}
                style={{ cursor: 'pointer' }}
              >
                <circle
                  r={22}
                  fill={isVpn ? '#eff6ff' : '#ffffff'}
                  stroke={isSelected ? '#0284c7' : isVpn ? '#3b82f6' : '#cbd5e1'}
                  strokeWidth={isSelected ? 3 : isVpn ? 2 : 1.5}
                  filter="drop-shadow(0 1px 2px rgba(0,0,0,0.06))"
                />
                <text y={4} textAnchor="middle" fill="#1e293b" fontSize="12">
                  {isVpn ? '🛡️' : '🌐'}
                </text>
                <text y={34} textAnchor="middle" fill="#1e293b" fontSize="10" fontWeight="600" fontFamily="monospace">
                  {node.label}
                </text>
                {isVpn && (
                  <text y={46} textAnchor="middle" fill="#2563eb" fontSize="8" fontWeight="700">
                    CORP VPN
                  </text>
                )}
              </g>
            );
          })}

          {/* Host Nodes */}
          {hostNodes.map(node => {
            const pos = hostPositions.get(node.id) || { x: hostX, y: 0 };
            const isSelected = selectedNodeId === node.id;
            const isNovel = node.isNovel;
            const isCritical = node.isCritical;

            let borderColor = '#16a34a'; // Baseline green
            let bgColor = '#f0fdf4';
            let icon = '🖥️';

            if (isCritical) {
              borderColor = '#dc2626'; // Red for critical domain controller/vault
              bgColor = '#fef2f2';
              icon = '🚨';
            } else if (isNovel) {
              borderColor = '#ea580c'; // Amber for unfamiliar
              bgColor = '#fff7ed';
              icon = '⚠️';
            }

            return (
              <g 
                key={node.id} 
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNodeId(selectedNodeId === node.id ? null : node.id)}
                style={{ cursor: 'pointer' }}
              >
                <rect
                  x={-60}
                  y={-18}
                  width={120}
                  height={36}
                  rx={6}
                  fill={bgColor}
                  stroke={isSelected ? '#0284c7' : borderColor}
                  strokeWidth={isSelected ? 2.5 : isCritical ? 2 : 1.5}
                  strokeDasharray={isNovel && !isCritical ? '4,3' : undefined}
                  filter="drop-shadow(0 1px 2px rgba(0,0,0,0.06))"
                />
                <text x={-46} y={4} fontSize="12">
                  {icon}
                </text>
                <text x={-26} y={4} fill="#0f172a" fontSize="10" fontWeight="700" fontFamily="monospace">
                  {node.label}
                </text>
                <text y={30} textAnchor="middle" fill={isCritical ? '#991b1b' : isNovel ? '#c2410c' : '#166534'} fontSize="8" fontWeight="700">
                  {isCritical ? 'TIER-0 CRITICAL' : isNovel ? 'NOVEL EXPANSION' : 'BASELINE HABITUAL'}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode ? (
        <div 
          style={{ 
            marginTop: 12, 
            padding: '10px 14px', 
            backgroundColor: '#ffffff', 
            borderRadius: 4, 
            border: '1px solid #cbd5e1',
            fontSize: 11,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}
        >
          <div>
            <span style={{ fontWeight: 700, color: '#0f172a' }}>
              Selected {selectedNode.type}: {selectedNode.label}
            </span>
            <span style={{ color: 'var(--slate-500)', marginLeft: 8 }}>
              Successes: <strong style={{ color: '#16a34a' }}>{selectedNode.successCount}</strong> &bull; Failures: <strong style={{ color: '#dc2626' }}>{selectedNode.failCount}</strong>
            </span>
            {selectedNode.details && (
              <span style={{ marginLeft: 10, color: 'var(--slate-600)' }}>
                {Object.entries(selectedNode.details).map(([k, v]) => `${k}: ${v}`).join(' | ')}
              </span>
            )}
          </div>
          <button 
            className="btn btn-secondary btn-sm" 
            style={{ fontSize: 10, padding: '2px 6px' }}
            onClick={() => setSelectedNodeId(null)}
          >
            Clear Selection
          </button>
        </div>
      ) : (
        <div style={{ marginTop: 8, fontSize: 10, color: 'var(--slate-500)', textAlign: 'center' }}>
          💡 Click on any node or server above to highlight connection paths and inspect details.
        </div>
      )}
    </div>
  );
};
