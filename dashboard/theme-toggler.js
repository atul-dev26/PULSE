(function () {
  // --- View Transitions Math & Logic (Translated exactly from React) ---
  function polygonCollapsed(point, vertexCount) {
    var pairs = Array.from({ length: vertexCount }, function () { return point; }).join(", ");
    return "polygon(" + pairs + ")";
  }

  function getThemeTransitionClipPaths(variant, cx, cy, maxRadius, viewportWidth, viewportHeight) {
    var toX = function (x) { return ((x / viewportWidth) * 100) + "%"; };
    var toY = function (y) { return ((y / viewportHeight) * 100) + "%"; };
    var point = function (x, y) { return toX(x) + " " + toY(y); };
    var toRadius = function (r) { return ((r / (Math.hypot(viewportWidth, viewportHeight) / Math.SQRT2)) * 100) + "%"; };

    switch (variant) {
      case "square": {
        var halfW = Math.max(cx, viewportWidth - cx);
        var halfH = Math.max(cy, viewportHeight - cy);
        var halfSide = Math.max(halfW, halfH) * 1.05;
        var end = [
          point(cx - halfSide, cy - halfSide),
          point(cx + halfSide, cy - halfSide),
          point(cx + halfSide, cy + halfSide),
          point(cx - halfSide, cy + halfSide),
        ].join(", ");
        return [polygonCollapsed(point(cx, cy), 4), "polygon(" + end + ")"];
      }
      case "triangle": {
        var scale = maxRadius * 2.2;
        var dx = (Math.sqrt(3) / 2) * scale;
        var verts = [
          point(cx, cy - scale),
          point(cx + dx, cy + 0.5 * scale),
          point(cx - dx, cy + 0.5 * scale),
        ].join(", ");
        return [polygonCollapsed(point(cx, cy), 3), "polygon(" + verts + ")"];
      }
      case "diamond": {
        var R = maxRadius * Math.SQRT2;
        var end = [
          point(cx, cy - R),
          point(cx + R, cy),
          point(cx, cy + R),
          point(cx - R, cy),
        ].join(", ");
        return [polygonCollapsed(point(cx, cy), 4), "polygon(" + end + ")"];
      }
      case "hexagon": {
        var R = maxRadius * Math.SQRT2;
        var verts = [];
        for (var i = 0; i < 6; i++) {
          var a = -Math.PI / 2 + (i * Math.PI) / 3;
          verts.push(point(cx + R * Math.cos(a), cy + R * Math.sin(a)));
        }
        return [polygonCollapsed(point(cx, cy), 6), "polygon(" + verts.join(", ") + ")"];
      }
      case "rectangle": {
        var halfW = Math.max(cx, viewportWidth - cx);
        var halfH = Math.max(cy, viewportHeight - cy);
        var end = [
          point(cx - halfW, cy - halfH),
          point(cx + halfW, cy - halfH),
          point(cx + halfW, cy + halfH),
          point(cx - halfW, cy + halfH),
        ].join(", ");
        return [polygonCollapsed(point(cx, cy), 4), "polygon(" + end + ")"];
      }
      case "star": {
        var R = maxRadius * Math.SQRT2 * 1.03;
        var innerRatio = 0.42;
        var starPolygon = function (radius) {
          var verts = [];
          for (var i = 0; i < 5; i++) {
            var outerA = -Math.PI / 2 + (i * 2 * Math.PI) / 5;
            verts.push(point(cx + radius * Math.cos(outerA), cy + radius * Math.sin(outerA)));
            var innerA = outerA + Math.PI / 5;
            verts.push(point(cx + radius * innerRatio * Math.cos(innerA), cy + radius * innerRatio * Math.sin(innerA)));
          }
          return "polygon(" + verts.join(", ") + ")";
        };
        var startR = Math.max(2, R * 0.025);
        return [starPolygon(startR), starPolygon(R)];
      }
      case "circle":
      default:
        return [
          "circle(0% at " + point(cx, cy) + ")",
          "circle(" + toRadius(maxRadius) + " at " + point(cx, cy) + ")",
        ];
    }
  }

  // --- Initial Theme Load ---
  var savedTheme = localStorage.getItem("theme");
  var isDark = savedTheme === "dark";
  if (isDark) {
    document.documentElement.classList.add("dark");
  }

  // --- Styles Injection ---
  var style = document.createElement("style");
  style.textContent = [
    "html.dark {",
    "  --bg: #171812;",
    "  --card-bg: #22241b;",
    "  --card-border: #33362a;",
    "  --text-primary: #F4F1EA;",
    "  --text-secondary: #A3A097;",
    "  --text-muted: #737068;",
    "  --sidebar-bg: #14150e;",
    "  --sidebar-active: #8B9D6A;",
    "  --sidebar-active-text: #171812;",
    "  --accent: #8B9D6A;",
    "  color-scheme: dark;",
    "}",
    "",
    "::view-transition-old(root),",
    "::view-transition-new(root) {",
    "  animation: none;",
    "  mix-blend-mode: normal;",
    "}",
    "[data-magicui-theme-vt='active']::view-transition-old(root) {",
    "  z-index: -1;",
    "}",
    "[data-magicui-theme-vt='active']::view-transition-new(root) {",
    "  clip-path: var(--magicui-theme-vt-clip-from);",
    "}",
    "[data-magicui-theme-vt='active']::view-transition-group(root) {",
    "  animation-duration: var(--magicui-theme-toggle-vt-duration);",
    "}",
    "",
    ".magicui-theme-toggler {",
    "  display: flex;",
    "  align-items: center;",
    "  justify-content: center;",
    "  width: 38px;",
    "  height: 38px;",
    "  border-radius: 8px;",
    "  background: transparent;",
    "  border: 1px solid var(--card-border, #D4D0C6);",
    "  color: var(--text-secondary, #6B6860);",
    "  cursor: pointer;",
    "  transition: all 0.2s;",
    "  z-index: 9999;",
    "}",
    ".magicui-theme-toggler:hover {",
    "  background: rgba(139, 157, 106, 0.1);",
    "  color: var(--accent, #4A5D23);",
    "  border-color: var(--accent, #4A5D23);",
    "}",
    ".magicui-theme-toggler svg {",
    "  width: 18px;",
    "  height: 18px;",
    "}",
  ].join("\n");
  document.head.appendChild(style);

  // --- SVG Icons (Lucide Sun & Moon) ---
  var sunIcon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>';
  var moonIcon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>';

  // --- Button Creation ---
  var btn = document.createElement("button");
  btn.type = "button";
  btn.className = "magicui-theme-toggler";
  btn.setAttribute("aria-label", "Toggle theme");
  btn.innerHTML = isDark ? sunIcon : moonIcon;

  // Insert into .header-right if it exists, else fixed top-right
  var headerRight = document.querySelector(".header-right");
  if (headerRight) {
    headerRight.insertBefore(btn, headerRight.firstChild);
  } else {
    btn.style.position = "fixed";
    btn.style.top = "16px";
    btn.style.right = "40px";
    document.body.appendChild(btn);
  }

  // --- Toggle Logic (View Transitions API) ---
  var isTransitioning = false;
  var activeAnim = null;

  btn.addEventListener("click", function () {
    if (isTransitioning || document.documentElement.dataset.magicuiThemeVt === "active") return;

    var root = document.documentElement;
    var duration = 500;
    var shape = "circle"; // Change to "star", "hexagon", "diamond", etc.

    var viewportWidth = window.innerWidth;
    var viewportHeight = window.innerHeight;
    var rect = btn.getBoundingClientRect();
    var x = rect.left + rect.width / 2;
    var y = rect.top + rect.height / 2;

    var maxRadius = Math.hypot(Math.max(x, viewportWidth - x), Math.max(y, viewportHeight - y));

    var applyTheme = function () {
      isDark = !root.classList.contains("dark");
      root.classList.toggle("dark");
      localStorage.setItem("theme", isDark ? "dark" : "light");
      btn.innerHTML = isDark ? sunIcon : moonIcon;
    };

    // Fallback for browsers without View Transitions API
    if (typeof document.startViewTransition !== "function") {
      applyTheme();
      return;
    }

    var clipPath = getThemeTransitionClipPaths(shape, x, y, maxRadius, viewportWidth, viewportHeight);

    root.dataset.magicuiThemeVt = "active";
    root.style.setProperty("--magicui-theme-toggle-vt-duration", duration + "ms");
    root.style.setProperty("--magicui-theme-vt-clip-from", clipPath[0]);

    var cleanup = function () {
      isTransitioning = false;
      delete root.dataset.magicuiThemeVt;
      root.style.removeProperty("--magicui-theme-toggle-vt-duration");
      root.style.removeProperty("--magicui-theme-vt-clip-from");
      if (activeAnim) {
        activeAnim.cancel();
        activeAnim = null;
      }
    };

    isTransitioning = true;
    var transition = document.startViewTransition(function () {
      applyTheme();
    });

    if (transition.finished && typeof transition.finished.finally === "function") {
      transition.finished.finally(cleanup).catch(function () { });
    } else {
      cleanup();
    }

    if (transition.ready && typeof transition.ready.then === "function") {
      transition.ready.then(function () {
        var anim = document.documentElement.animate(
          { clipPath: clipPath },
          {
            duration: duration,
            easing: shape === "star" ? "linear" : "ease-in-out",
            fill: "forwards",
            pseudoElement: "::view-transition-new(root)",
          }
        );
        activeAnim = anim;
      }).catch(function () { });
    }
  });

})();
