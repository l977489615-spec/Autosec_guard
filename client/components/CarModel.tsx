import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Line, Box, Cone, Float, Html, Sphere } from '@react-three/drei';
import * as THREE from 'three';

interface CarModelProps {
  activeZones: string[]; // e.g., 'wifi', 'bluetooth', 'ivi', 'canbus'
}

export const CarModel: React.FC<CarModelProps> = ({ activeZones }) => {
  const groupRef = useRef<THREE.Group>(null);

  // Auto-rotate the car slightly for 3D effect
  useFrame((state) => {
    if (groupRef.current) {
      groupRef.current.rotation.y = Math.sin(state.clock.elapsedTime * 0.2) * 0.3 - 0.5;
    }
  });

  // Calculate colors based on active zones
  // Map phase name or category to zone
  const isWifiActive = activeZones.includes('wireless') || activeZones.includes('wifi');
  // Map 'recon' to bluetooth scanning visually or explicitly 'bluetooth'
  const isBtActive = activeZones.includes('recon') || activeZones.includes('bluetooth');
  // 'network' or 'application' hits the IVI
  const isIviActive = activeZones.includes('network') || activeZones.includes('application');
  const isCanActive = activeZones.includes('canbus');
  const isGatewayActive = activeZones.includes('advanced');

  const wireframeColor = '#0eb5c2'; // cyan-500
  const activeColor = '#ef4444'; // red-500
  const scanningColor = '#f59e0b'; // amber-500

  // Standard material for the wireframe car body
  const bodyMaterial = useMemo(() => new THREE.MeshBasicMaterial({
    color: wireframeColor,
    wireframe: true,
    transparent: true,
    opacity: 0.3
  }), [wireframeColor]);

  // Material for active/attacked zones
  const dangerMaterial = useMemo(() => new THREE.MeshBasicMaterial({
    color: activeColor,
    wireframe: true,
    transparent: true,
    opacity: 0.8
  }), [activeColor]);

  const scanningMaterial = useMemo(() => new THREE.MeshBasicMaterial({
    color: scanningColor,
    wireframe: true,
    transparent: true,
    opacity: 0.8
  }), [scanningColor]);

  return (
    <group ref={groupRef} position={[0, -0.5, 0]}>
      <Float speed={2} rotationIntensity={0.1} floatIntensity={0.5}>
        
        {/* === Chassis (Main Body) === */}
        <Box args={[4.5, 0.8, 2]} position={[0, 0.4, 0]}>
          <primitive object={bodyMaterial} attach="material" />
        </Box>

        {/* === Cabin (Top) === */}
        <Box args={[2.5, 0.7, 1.8]} position={[-0.2, 1.15, 0]}>
          <primitive object={bodyMaterial} attach="material" />
        </Box>

        {/* === Wheels === */}
        {[-1.5, 1.5].map((x, i) => (
          [-1, 1].map((z, j) => (
            <Box key={`wheel-${i}-${j}`} args={[0.6, 0.6, 0.2]} position={[x, 0, z * 1.05]}>
              <meshBasicMaterial color="#334155" wireframe={true} />
            </Box>
          ))
        ))}

        {/* ========================================================= */}
        {/* ==================== ATTACK ZONES ======================= */}
        {/* ========================================================= */}

        {/* 1. Wireless Antenna (Wi-Fi / Network) */}
        <group position={[-1, 1.55, 0]}>
          <Cone args={[0.05, 0.3, 8]} position={[0, 0.15, 0]}>
            <primitive object={isWifiActive ? dangerMaterial : bodyMaterial} attach="material" />
          </Cone>
          {isWifiActive && (
            <Html center position={[0, 0.5, 0]}>
              <div className="bg-red-900/80 border border-red-500 text-red-300 text-[10px] px-2 py-0.5 rounded whitespace-nowrap animate-pulse">
                WIFI COMPROMISED
              </div>
            </Html>
          )}
        </group>

        {/* 2. Bluetooth / T-Box Module (Shark fin area) */}
        <group position={[0.8, 1.55, 0]}>
          <Box args={[0.2, 0.1, 0.2]} position={[0, 0.05, 0]}>
             <primitive object={isBtActive ? scanningMaterial : bodyMaterial} attach="material" />
          </Box>
          {isBtActive && (
            <Html center position={[0, 0.4, 0]}>
              <div className="bg-amber-900/80 border border-amber-500 text-amber-300 text-[10px] px-2 py-0.5 rounded whitespace-nowrap animate-pulse">
                BLUETOOTH SCANNING
              </div>
            </Html>
          )}
        </group>

        {/* 3. IVI Headunit (Center Console) */}
        <group position={[0.3, 0.9, 0]}>
          <Box args={[0.4, 0.4, 0.8]}>
            <primitive object={isIviActive ? dangerMaterial : new THREE.MeshBasicMaterial({ color: '#1e293b', transparent: true, opacity: 0.8 })} attach="material" />
          </Box>
          {isIviActive && (
             <Html center position={[0, 0.6, 0]}>
               <div className="bg-red-900/80 border border-red-500 text-red-300 text-[10px] px-2 py-0.5 rounded whitespace-nowrap animate-pulse">
                 IVI ROOT SHELL
               </div>
             </Html>
          )}
        </group>

        {/* 4. Security Gateway (SEC-GW) */}
        <group position={[1.5, 0.5, 0]}>
           <Sphere args={[0.2, 8, 8]}>
             <primitive object={isGatewayActive ? dangerMaterial : new THREE.MeshBasicMaterial({ color: '#3b82f6', wireframe: true })} attach="material" />
           </Sphere>
           <Html center position={[0, -0.4, 0]}>
             <span className="text-[9px] text-blue-400 font-mono bg-black/50 px-1 rounded">SEC-GW</span>
           </Html>
        </group>

        {/* 5. CAN Bus lines (Running through chassis) */}
        <group position={[0, 0.2, 0]}>
          {/* Main CAN trunk */}
          <Sphere args={[0.05, 4, 4]} position={[-1.5, 0, 0]}>
             <primitive object={isCanActive ? dangerMaterial : bodyMaterial} attach="material" />
          </Sphere>
          <Sphere args={[0.05, 4, 4]} position={[1.5, 0, 0]}>
             <primitive object={isCanActive ? dangerMaterial : bodyMaterial} attach="material" />
          </Sphere>
          <Line
            points={[[-1.5, 0, 0], [1.5, 0, 0]]}
            color={isCanActive ? activeColor : wireframeColor}
            lineWidth={isCanActive ? 3 : 1}
          />
          {/* IVI to CAN */}
          <Line
            points={[[0.3, 0.7, 0], [0.3, 0, 0]]}
            color={isCanActive || isIviActive ? activeColor : wireframeColor}
            lineWidth={isCanActive ? 3 : 1}
          />
          {isCanActive && (
             <Html center position={[-1, -0.3, 0.5]}>
               <div className="bg-red-900/80 border border-red-500 text-red-300 text-[10px] px-2 py-0.5 rounded whitespace-nowrap animate-pulse">
                 CAN BUS INJECTION
               </div>
             </Html>
          )}
        </group>

      </Float>
    </group>
  );
};
