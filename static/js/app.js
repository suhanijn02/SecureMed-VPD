// SecureMed VPD - small progressive enhancements (no inline scripts, CSP-friendly)
(function () {
  // Tooltips for any element with data-tip
  const tip = document.getElementById("tip");
  document.addEventListener("mouseover", (e) => {
    const el = e.target.closest("[data-tip]");
    if (!el || !tip) return;
    tip.textContent = el.getAttribute("data-tip");
    tip.classList.add("show");
  });
  document.addEventListener("mousemove", (e) => {
    if (!tip || !tip.classList.contains("show")) return;
    const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
    tip.style.left = x + "px";
    tip.style.top = e.clientY + 16 + "px";
  });
  document.addEventListener("mouseout", (e) => {
    if (tip && e.target.closest("[data-tip]")) tip.classList.remove("show");
  });

  // Confirmation for destructive forms
  document.querySelectorAll("form[data-confirm]").forEach((f) =>
    f.addEventListener("submit", (e) => {
      if (!confirm(f.getAttribute("data-confirm"))) e.preventDefault();
    })
  );

  // Login page: click a demo account to fill the form
  document.querySelectorAll(".demo-accounts tbody tr").forEach((tr) =>
    tr.addEventListener("click", () => {
      const u = document.getElementById("username");
      const p = document.getElementById("password");
      if (!u || !p) return;
      u.value = tr.cells[0].textContent.trim();
      p.value = tr.cells[1].textContent.trim();
      p.focus();
    })
  );

  // SQL console: example buttons
  document.querySelectorAll(".example").forEach((b) =>
    b.addEventListener("click", () => {
      const ta = document.getElementById("sql");
      if (ta) { ta.value = b.getAttribute("data-sql"); ta.focus(); }
    })
  );
})();
