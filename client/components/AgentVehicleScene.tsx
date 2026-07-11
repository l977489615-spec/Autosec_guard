import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { RoundedBoxGeometry } from 'three/examples/jsm/geometries/RoundedBoxGeometry.js';

interface AgentVehicleSceneProps {
  activeZones: string[];
  autoRotate: boolean;
  onFailure: () => void;
  compact?: boolean;
}

type Beacon = {
  id: string;
  ring: THREE.Mesh<THREE.TorusGeometry, THREE.MeshBasicMaterial>;
  core: THREE.Mesh<THREE.IcosahedronGeometry, THREE.MeshBasicMaterial>;
  light: THREE.PointLight;
};

const ZONES = [
  { id: 'recon', label: '外部侦察', left: '13%', top: '24%', color: '#FFB02E' },
  { id: 'network', label: '车载网络', left: '39%', top: '15%', color: '#4B7CFF' },
  { id: 'wireless', label: '无线接口', left: '70%', top: '18%', color: '#39E7FF' },
  { id: 'execute', label: '执行验证', left: '85%', top: '43%', color: '#FF3D71' },
  { id: 'assess', label: '证据评估', left: '61%', top: '73%', color: '#8B7CFF' },
] as const;

const BEACON_POSITIONS: Record<string, THREE.Vector3> = {
  recon: new THREE.Vector3(-1.8, 0.42, 0.82),
  network: new THREE.Vector3(-0.2, 0.78, 0.78),
  wireless: new THREE.Vector3(0.65, 1.52, 0.12),
  execute: new THREE.Vector3(1.62, 0.38, 0.72),
  assess: new THREE.Vector3(0.45, 0.22, -0.72),
};

const makeCabinGeometry = () => {
  const vertices = new Float32Array([
    -1.15, .25, -.72,   .95, .25, -.72,   .62, 1.22, -.61,  -.62, 1.22, -.61,
    -1.15, .25,  .72,   .95, .25,  .72,   .62, 1.22,  .61,  -.62, 1.22,  .61,
  ]);
  const indices = [
    0,1,2, 0,2,3, 4,6,5, 4,7,6, 3,2,6, 3,6,7,
    0,4,5, 0,5,1, 0,3,7, 0,7,4, 1,5,6, 1,6,2,
  ];
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute('position', new THREE.BufferAttribute(vertices, 3));
  geometry.setIndex(indices);
  geometry.computeVertexNormals();
  return geometry;
};

const addEdges = (mesh: THREE.Mesh, color = '#42DFF5', opacity = .34) => {
  const edges = new THREE.LineSegments(
    new THREE.EdgesGeometry(mesh.geometry, 24),
    new THREE.LineBasicMaterial({ color, transparent: true, opacity, blending: THREE.AdditiveBlending }),
  );
  mesh.add(edges);
};

const createVehicle = () => {
  const vehicle = new THREE.Group();
  vehicle.name = 'digital-twin-vehicle';

  const bodyMaterial = new THREE.MeshPhysicalMaterial({
    color: '#0B4E69',
    emissive: '#052D43',
    emissiveIntensity: .55,
    metalness: .76,
    roughness: .2,
    clearcoat: 1,
    clearcoatRoughness: .16,
  });
  const accentMaterial = new THREE.MeshPhysicalMaterial({
    color: '#116A86', emissive: '#07384D', emissiveIntensity: .7,
    metalness: .7, roughness: .24, clearcoat: .85,
  });
  const glassMaterial = new THREE.MeshPhysicalMaterial({
    color: '#071C32', emissive: '#0A3F58', emissiveIntensity: .75,
    metalness: .25, roughness: .06, transmission: .22, transparent: true, opacity: .9,
  });

  const lowerBody = new THREE.Mesh(new RoundedBoxGeometry(4.55, .72, 1.64, 5, .18), bodyMaterial);
  lowerBody.position.y = -.05;
  lowerBody.castShadow = true;
  lowerBody.receiveShadow = true;
  addEdges(lowerBody, '#45E8FF', .48);
  vehicle.add(lowerBody);

  const hood = new THREE.Mesh(new RoundedBoxGeometry(1.45, .28, 1.55, 4, .12), accentMaterial);
  hood.position.set(1.62, .36, 0);
  hood.rotation.z = -.035;
  hood.castShadow = true;
  addEdges(hood, '#39E7FF', .34);
  vehicle.add(hood);

  const rearDeck = new THREE.Mesh(new RoundedBoxGeometry(.78, .24, 1.55, 4, .1), accentMaterial);
  rearDeck.position.set(-1.86, .34, 0);
  rearDeck.castShadow = true;
  vehicle.add(rearDeck);

  const cabin = new THREE.Mesh(makeCabinGeometry(), glassMaterial);
  cabin.position.set(-.1, .18, 0);
  cabin.castShadow = true;
  addEdges(cabin, '#5DEBFF', .55);
  vehicle.add(cabin);

  const roofRailMaterial = new THREE.MeshBasicMaterial({ color: '#6FEFFF', transparent: true, opacity: .58 });
  [-.58, .58].forEach((z) => {
    const rail = new THREE.Mesh(new THREE.CylinderGeometry(.018, .018, 1.42, 8), roofRailMaterial);
    rail.rotation.z = Math.PI / 2;
    rail.position.set(-.04, 1.46, z);
    vehicle.add(rail);
  });

  const tireMaterial = new THREE.MeshStandardMaterial({ color: '#02070D', roughness: .54, metalness: .18 });
  const rimMaterial = new THREE.MeshPhysicalMaterial({
    color: '#7BDAE7', emissive: '#0B7189', emissiveIntensity: .9, metalness: .9, roughness: .12,
  });
  const brakeMaterial = new THREE.MeshBasicMaterial({ color: '#FF3D71', toneMapped: false });
  [-1.5, 1.5].forEach((x) => {
    [-.88, .88].forEach((z) => {
      const wheel = new THREE.Group();
      const tire = new THREE.Mesh(new THREE.CylinderGeometry(.45, .45, .24, 28, 1), tireMaterial);
      tire.rotation.x = Math.PI / 2;
      tire.castShadow = true;
      wheel.add(tire);
      const rim = new THREE.Mesh(new THREE.CylinderGeometry(.265, .265, .255, 10, 1), rimMaterial);
      rim.rotation.x = Math.PI / 2;
      wheel.add(rim);
      const hub = new THREE.Mesh(new THREE.CylinderGeometry(.07, .07, .27, 12), brakeMaterial);
      hub.rotation.x = Math.PI / 2;
      wheel.add(hub);
      for (let spokeIndex = 0; spokeIndex < 5; spokeIndex += 1) {
        const spoke = new THREE.Mesh(new THREE.BoxGeometry(.035, .23, .025), rimMaterial);
        spoke.rotation.z = (spokeIndex / 5) * Math.PI * 2;
        spoke.position.z = z > 0 ? .14 : -.14;
        wheel.add(spoke);
      }
      wheel.position.set(x, -.38, z);
      vehicle.add(wheel);
    });
  });

  const lightGeometry = new THREE.BoxGeometry(.07, .11, .36);
  [[2.28, '#E9FCFF'], [-2.28, '#FF3D71']].forEach(([x, color]) => {
    [-.53, .53].forEach((z) => {
      const light = new THREE.Mesh(lightGeometry, new THREE.MeshBasicMaterial({ color: color as string, toneMapped: false }));
      light.position.set(x as number, .15, z);
      vehicle.add(light);
    });
  });

  const canLine = new THREE.Line(
    new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(-1.55, .06, 0), new THREE.Vector3(-.3, .06, 0),
      new THREE.Vector3(.2, .48, 0), new THREE.Vector3(1.52, .06, 0),
    ]),
    new THREE.LineBasicMaterial({ color: '#4B7CFF', transparent: true, opacity: .9, blending: THREE.AdditiveBlending }),
  );
  vehicle.add(canLine);

  return vehicle;
};

const createFloorMaterial = () => new THREE.ShaderMaterial({
  transparent: true,
  depthWrite: false,
  uniforms: { uColor: { value: new THREE.Color('#26CFEA') }, uTime: { value: 0 } },
  vertexShader: `
    varying vec2 vUv;
    void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }
  `,
  fragmentShader: `
    varying vec2 vUv;
    uniform vec3 uColor;
    uniform float uTime;
    float line(float value, float width) { return 1.0 - smoothstep(width, width + 0.018, abs(fract(value) - .5)); }
    void main() {
      vec2 centered = vUv - .5;
      float grid = max(line(vUv.x * 24.0, .44), line(vUv.y * 16.0, .44));
      float radial = 1.0 - smoothstep(.1, .73, length(centered));
      float pulse = .74 + .26 * sin(uTime * .8 - length(centered) * 10.0);
      gl_FragColor = vec4(uColor, grid * radial * pulse * .34);
    }
  `,
});

const createScanMaterial = () => new THREE.ShaderMaterial({
  transparent: true,
  side: THREE.DoubleSide,
  depthWrite: false,
  blending: THREE.AdditiveBlending,
  uniforms: { uColor: { value: new THREE.Color('#39E7FF') }, uTime: { value: 0 } },
  vertexShader: `
    varying vec2 vUv;
    void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }
  `,
  fragmentShader: `
    varying vec2 vUv;
    uniform vec3 uColor;
    uniform float uTime;
    void main() {
      float edge = smoothstep(0.0, .14, vUv.x) * smoothstep(1.0, .86, vUv.x);
      float vertical = smoothstep(0.0, .12, vUv.y) * smoothstep(1.0, .72, vUv.y);
      float bands = .36 + .64 * pow(max(0.0, sin(vUv.y * 72.0 - uTime * 4.0)), 8.0);
      gl_FragColor = vec4(uColor, edge * vertical * bands * .27);
    }
  `,
});

const disposeObject = (object: THREE.Object3D) => {
  object.traverse((child) => {
    const mesh = child as THREE.Mesh;
    mesh.geometry?.dispose?.();
    if (Array.isArray(mesh.material)) mesh.material.forEach((material) => material.dispose());
    else (mesh.material as THREE.Material | undefined)?.dispose?.();
  });
};

const AgentVehicleScene: React.FC<AgentVehicleSceneProps> = ({ activeZones, autoRotate, onFailure, compact = false }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const failureRef = useRef(onFailure);
  const activeRef = useRef(new Set(activeZones));
  const autoRotateRef = useRef(autoRotate);
  const pointerRef = useRef({ dragging: false, x: 0, yaw: -.28, targetYaw: -.28 });
  const [dragging, setDragging] = useState(false);

  useEffect(() => { failureRef.current = onFailure; }, [onFailure]);
  useEffect(() => { activeRef.current = new Set(activeZones); }, [activeZones]);
  useEffect(() => { autoRotateRef.current = autoRotate; }, [autoRotate]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: 'high-performance' });
    } catch {
      failureRef.current();
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, compact ? 1.45 : 1.8));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.3;
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFShadowMap;

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2('#06101C', .072);
    const camera = new THREE.PerspectiveCamera(compact ? 38 : 36, 1, .1, 60);
    camera.position.set(compact ? 5.9 : 4.75, compact ? 2.8 : 2.35, compact ? 7.8 : 6.2);
    camera.lookAt(0, .25, 0);

    scene.add(new THREE.HemisphereLight('#8EEFFF', '#04101B', 2.1));
    const keyLight = new THREE.DirectionalLight('#BDEEFF', 4.5);
    keyLight.position.set(4, 7, 5);
    keyLight.castShadow = true;
    keyLight.shadow.mapSize.set(compact ? 512 : 1024, compact ? 512 : 1024);
    scene.add(keyLight);
    const blueRim = new THREE.PointLight('#4B7CFF', 15, 12, 2);
    blueRim.position.set(-3.5, 1.5, -2.8);
    scene.add(blueRim);
    const cyanRim = new THREE.PointLight('#39E7FF', 12, 10, 2);
    cyanRim.position.set(3.2, .8, 3.2);
    scene.add(cyanRim);

    const stage = new THREE.Group();
    stage.rotation.y = pointerRef.current.yaw;
    scene.add(stage);
    const vehicle = createVehicle();
    vehicle.position.y = .06;
    stage.add(vehicle);

    const floorMaterial = createFloorMaterial();
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(15, 10), floorMaterial);
    floor.rotation.x = -Math.PI / 2;
    floor.position.y = -.88;
    scene.add(floor);

    const scanMaterial = createScanMaterial();
    const scanCurtain = new THREE.Mesh(new THREE.PlaneGeometry(3.4, 3.8, 1, 1), scanMaterial);
    scanCurtain.rotation.y = Math.PI / 2;
    scanCurtain.position.y = .58;
    stage.add(scanCurtain);

    const halo = new THREE.Mesh(
      new THREE.RingGeometry(2.5, 2.56, 96),
      new THREE.MeshBasicMaterial({ color: '#39E7FF', transparent: true, opacity: .23, blending: THREE.AdditiveBlending, side: THREE.DoubleSide }),
    );
    halo.rotation.x = -Math.PI / 2;
    halo.position.y = -.84;
    scene.add(halo);

    const beacons: Beacon[] = ZONES.map((zone) => {
      const color = new THREE.Color(zone.color);
      const group = new THREE.Group();
      group.position.copy(BEACON_POSITIONS[zone.id]);
      const ring = new THREE.Mesh(
        new THREE.TorusGeometry(.13, .012, 8, 36),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .28, blending: THREE.AdditiveBlending, toneMapped: false }),
      );
      ring.rotation.x = Math.PI / 2;
      group.add(ring);
      const core = new THREE.Mesh(
        new THREE.IcosahedronGeometry(.035, 1),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .5, toneMapped: false }),
      );
      group.add(core);
      const light = new THREE.PointLight(color, 0, 1.6, 2);
      group.add(light);
      stage.add(group);
      return { id: zone.id, ring, core, light };
    });

    const particleCount = compact ? 90 : 180;
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount; i += 1) {
      particlePositions[i * 3] = (Math.random() - .5) * 12;
      particlePositions[i * 3 + 1] = Math.random() * 4.8 - .7;
      particlePositions[i * 3 + 2] = (Math.random() - .5) * 8;
    }
    const particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particles = new THREE.Points(
      particleGeometry,
      new THREE.PointsMaterial({ color: '#6DEBFF', size: .018, transparent: true, opacity: .36, blending: THREE.AdditiveBlending }),
    );
    scene.add(particles);

    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const startedAt = performance.now();
    let visible = true;
    const observer = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; }, { threshold: .02 });
    observer.observe(canvas);

    const resize = () => {
      const width = Math.max(canvas.clientWidth, 1);
      const height = Math.max(canvas.clientHeight, 1);
      const pixelRatio = renderer.getPixelRatio();
      if (canvas.width !== Math.floor(width * pixelRatio) || canvas.height !== Math.floor(height * pixelRatio)) {
        renderer.setSize(width, height, false);
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
      }
    };

    const animate = () => {
      if (!visible) return;
      resize();
      const elapsed = (performance.now() - startedAt) / 1000;
      const pointer = pointerRef.current;
      if (autoRotateRef.current && !pointer.dragging && !reducedMotion) {
        pointer.targetYaw = -.28 + Math.sin(elapsed * .32) * .31;
      }
      pointer.yaw += (pointer.targetYaw - pointer.yaw) * .06;
      stage.rotation.y = pointer.yaw;
      vehicle.position.y = .06 + (reducedMotion ? 0 : Math.sin(elapsed * .9) * .025);
      scanCurtain.position.x = reducedMotion ? 0 : Math.sin(elapsed * .72) * 2.35;
      scanMaterial.uniforms.uTime.value = elapsed;
      floorMaterial.uniforms.uTime.value = elapsed;
      halo.rotation.z = elapsed * .05;
      particles.rotation.y = elapsed * .008;

      beacons.forEach((beacon, index) => {
        const isActive = activeRef.current.has(beacon.id);
        const pulse = .78 + Math.sin(elapsed * 3.2 + index) * .22;
        beacon.ring.rotation.z = elapsed * (index % 2 ? -.4 : .4);
        beacon.ring.scale.setScalar(isActive ? 1.15 + pulse * .34 : 1);
        beacon.ring.material.opacity = isActive ? .82 : .25;
        beacon.core.material.opacity = isActive ? 1 : .42;
        beacon.light.intensity = isActive ? 4.5 + pulse * 4 : 0;
      });

      renderer.render(scene, camera);
    };
    renderer.setAnimationLoop(animate);

    const contextLost = (event: Event) => { event.preventDefault(); failureRef.current(); };
    canvas.addEventListener('webglcontextlost', contextLost);
    return () => {
      observer.disconnect();
      renderer.setAnimationLoop(null);
      canvas.removeEventListener('webglcontextlost', contextLost);
      disposeObject(scene);
      renderer.dispose();
      // React Strict Mode performs a development-only setup/cleanup/setup cycle
      // while the same canvas is still mounted. Releasing the context there
      // makes the second setup fail. Only force-release after a real DOM unmount.
      window.setTimeout(() => {
        if (!canvas.isConnected) {
          renderer.forceContextLoss();
          canvas.width = 1;
          canvas.height = 1;
        }
      }, 0);
    };
  }, [compact]);

  const onPointerDown = (event: React.PointerEvent<HTMLCanvasElement>) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    pointerRef.current.dragging = true;
    pointerRef.current.x = event.clientX;
    setDragging(true);
  };
  const onPointerMove = (event: React.PointerEvent<HTMLCanvasElement>) => {
    if (!pointerRef.current.dragging) return;
    const delta = event.clientX - pointerRef.current.x;
    pointerRef.current.x = event.clientX;
    pointerRef.current.targetYaw += delta * .008;
  };
  const onPointerUp = (event: React.PointerEvent<HTMLCanvasElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    pointerRef.current.dragging = false;
    setDragging(false);
  };

  const active = new Set(activeZones);
  return (
    <div className="vehicle-scene relative h-full w-full overflow-hidden" role="img" aria-label={`3D 车辆攻击面，活动区域：${activeZones.join('、') || '无'}`}>
      <canvas
        ref={canvasRef}
        className={`h-full w-full touch-none ${dragging ? 'cursor-grabbing' : 'cursor-grab'}`}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      />
      <div className="pointer-events-none absolute inset-0">
        {ZONES.map((zone) => {
          const isActive = active.has(zone.id);
          return (
            <div key={zone.id} className="absolute -translate-x-1/2 -translate-y-1/2" style={{ left: zone.left, top: zone.top }}>
              <div className={`vehicle-zone ${isActive ? 'vehicle-zone-active' : ''}`} style={{ '--zone-color': zone.color } as React.CSSProperties}>
                <span className="vehicle-zone-dot" />{zone.label}
              </div>
            </div>
          );
        })}
      </div>
      <div className="pointer-events-none absolute bottom-3 right-4 font-mono text-[9px] tracking-[0.18em] text-cyan-100/45">DRAG TO ORBIT · THREE.JS / GLSL</div>
    </div>
  );
};

export default AgentVehicleScene;
