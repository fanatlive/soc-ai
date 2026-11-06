// Короткая Matrix-заставка (~0,5 с) при загрузке страницы. Не зависит от app.js и не меняет интерфейс сайта.
(() => {
  const root = document.getElementById("matrix-intro");
  if (!root) return;
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const canvas = root.querySelector("canvas");
  const ctx = canvas && canvas.getContext ? canvas.getContext("2d") : null;
  if (reduceMotion || !ctx) { root.remove(); return; }

  const GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789".split("");
  const FONT = 16, FRAME_MS = 45;
  const SHOW_MS = 300, FADE_MS = 200; // итого ≈ 0,5 с (должно совпадать с transition в intro.css)
  let drops = [], width = 0, height = 0, raf = 0, last = 0, finished = false;

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = FONT + "px monospace";
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, width, height);
    const count = Math.ceil(width / FONT);
    // капли стартуют по всему экрану, чтобы дождь был виден с первого кадра
    drops = Array.from({ length: count }, (_, i) => drops[i] ?? Math.floor(Math.random() * (height / FONT)));
    for (let i = 0; i < 24; i++) step(); // «прогрев»: сразу рисуем хвосты
  }

  function step() {
    ctx.fillStyle = "rgba(0, 0, 0, .1)"; // хвосты символов
    ctx.fillRect(0, 0, width, height);
    for (let i = 0; i < drops.length; i++) {
      const y = drops[i] * FONT;
      ctx.fillStyle = "#00ff41";
      ctx.fillText(GLYPHS[(Math.random() * GLYPHS.length) | 0], i * FONT, y);
      drops[i] = y > height && Math.random() > 0.975 ? 0 : drops[i] + 1;
    }
  }

  function frame(time) {
    raf = requestAnimationFrame(frame);
    if (time - last < FRAME_MS) return;
    last = time;
    step();
  }

  function finish() {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    window.removeEventListener("resize", resize);
    ["click", "keydown", "touchstart"].forEach((name) => window.removeEventListener(name, finish));
    root.classList.add("is-leaving");
    setTimeout(() => { cancelAnimationFrame(raf); root.remove(); }, FADE_MS + 40);
  }

  resize();
  window.addEventListener("resize", resize);
  ["click", "keydown", "touchstart"].forEach((name) => window.addEventListener(name, finish, { passive: true }));
  raf = requestAnimationFrame(frame);
  // отсчёт от начала загрузки страницы (а не от старта скрипта), чтобы заставка длилась ровно ≈ 0,5 с
  const timer = setTimeout(finish, Math.max(0, SHOW_MS - performance.now()));
})();
