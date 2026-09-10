// Exact SmoothCursor functionality translated to Vanilla JS
// Replicates the SVG and physics behaviors

(function () {
    const DESKTOP_POINTER_QUERY = "(any-hover: hover) and (any-pointer: fine)";
    let isEnabled = window.matchMedia(DESKTOP_POINTER_QUERY).matches;
    if (!isEnabled) return;

    // Inject CSS
    const style = document.createElement('style');
    style.innerHTML = `
        #magic-cursor-container {
            position: fixed;
            top: 0; left: 0;
            z-index: 99999;
            pointer-events: none;
            will-change: transform;
            opacity: 0;
            transition: opacity 0.15s ease;
            transform-origin: center center;
        }
        *, *::before, *::after { cursor: none !important; }
        body.splash-active #magic-cursor-container { opacity: 0 !important; }
    `;
    document.head.appendChild(style);

    // Exact SVG from SmoothCursorProps
    const cursorSvg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="50" height="54" viewBox="0 0 50 54" fill="none" style="scale: 0.5;">
      <g filter="url(#filter0_d_91_7928)">
        <path d="M42.6817 41.1495L27.5103 6.79925C26.7269 5.02557 24.2082 5.02558 23.3927 6.79925L7.59814 41.1495C6.75833 42.9759 8.52712 44.8902 10.4125 44.1954L24.3757 39.0496C24.8829 38.8627 25.4385 38.8627 25.9422 39.0496L39.8121 44.1954C41.6849 44.8902 43.4884 42.9759 42.6817 41.1495Z" fill="black"/>
        <path d="M43.7146 40.6933L28.5431 6.34306C27.3556 3.65428 23.5772 3.69516 22.3668 6.32755L6.57226 40.6778C5.3134 43.4156 7.97238 46.298 10.803 45.2549L24.7662 40.109C25.0221 40.0147 25.2999 40.0156 25.5494 40.1082L39.4193 45.254C42.2261 46.2953 44.9254 43.4347 43.7146 40.6933Z" stroke="white" stroke-width="2.25825"/>
      </g>
      <defs>
        <filter id="filter0_d_91_7928" x="0.602397" y="0.952444" width="49.0584" height="52.428" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">
          <feFlood flood-opacity="0" result="BackgroundImageFix" />
          <feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0" result="hardAlpha" />
          <feOffset dy="2.25825" />
          <feGaussianBlur stdDeviation="2.25825" />
          <feComposite in2="hardAlpha" operator="out" />
          <feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.08 0" />
          <feBlend mode="normal" in2="BackgroundImageFix" result="effect1_dropShadow_91_7928" />
          <feBlend mode="normal" in="SourceGraphic" in2="effect1_dropShadow_91_7928" result="shape" />
        </filter>
      </defs>
    </svg>`;

    const container = document.createElement('div');
    container.id = 'magic-cursor-container';
    container.innerHTML = cursorSvg;
    document.body.appendChild(container);

    let isVisible = false;

    // Target values based on pointer events
    let targetX = 0;
    let targetY = 0;
    let targetRotation = 0;
    let targetScale = 1;

    // Current animated values
    let cursorX = 0;
    let cursorY = 0;
    let rotation = 0;
    let scale = 1;

    let lastMousePos = { x: 0, y: 0 };
    let velocity = { x: 0, y: 0 };
    let lastUpdateTime = Date.now();
    let previousAngle = 0;
    let accumulatedRotation = 0;
    let timeout = null;

    function updateVelocity(currentPos) {
        const currentTime = Date.now();
        const deltaTime = currentTime - lastUpdateTime;

        if (deltaTime > 0) {
            velocity.x = (currentPos.x - lastMousePos.x) / deltaTime;
            velocity.y = (currentPos.y - lastMousePos.y) / deltaTime;
        }

        lastUpdateTime = currentTime;
        lastMousePos = currentPos;
    }

    let rafId = 0;
    const smoothPointerMove = (e) => {
        if (e.pointerType === "touch") return;

        if (!isVisible) {
            isVisible = true;
            container.style.opacity = '1';
            // Snap to position on first appearance
            cursorX = e.clientX;
            cursorY = e.clientY;
            targetX = e.clientX;
            targetY = e.clientY;
        }

        const currentPos = { x: e.clientX, y: e.clientY };
        updateVelocity(currentPos);

        const speed = Math.sqrt(Math.pow(velocity.x, 2) + Math.pow(velocity.y, 2));

        targetX = currentPos.x;
        targetY = currentPos.y;

        if (speed > 0.1) {
            const currentAngle = (Math.atan2(velocity.y, velocity.x) * (180 / Math.PI)) + 90;

            let angleDiff = currentAngle - previousAngle;
            if (angleDiff > 180) angleDiff -= 360;
            if (angleDiff < -180) angleDiff += 360;
            accumulatedRotation += angleDiff;

            targetRotation = accumulatedRotation;
            previousAngle = currentAngle;

            targetScale = 0.95;

            if (timeout !== null) {
                clearTimeout(timeout);
            }
            timeout = setTimeout(() => {
                targetScale = 1;
            }, 150);
        }
    };

    window.addEventListener("pointermove", (e) => {
        if (e.pointerType === "touch") return;
        if (rafId) return;
        rafId = requestAnimationFrame(() => {
            smoothPointerMove(e);
            rafId = 0;
        });
    }, { passive: true });

    // Physics Simulation Loop
    // Simulating react-motion springs with tuned lerp factors for similar feel
    function animate() {
        // High stiffness & damping for X/Y
        cursorX += (targetX - cursorX) * 0.45;
        cursorY += (targetY - cursorY) * 0.45;

        // Slightly softer for rotation
        rotation += (targetRotation - rotation) * 0.25;

        // Very fast scale return
        scale += (targetScale - scale) * 0.35;

        container.style.transform = `translate3d(${cursorX}px, ${cursorY}px, 0) translate(-50%, -50%) rotate(${rotation}deg) scale(${scale})`;

        requestAnimationFrame(animate);
    }
    requestAnimationFrame(animate);

})();
