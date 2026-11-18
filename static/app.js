// Enable the scan button only after the authorization box is ticked.
document.addEventListener("DOMContentLoaded", () => {
  const box = document.getElementById("authorized"), btn = document.getElementById("scanBtn");
  if (!box || !btn) return;
  const sync = () => { btn.disabled = !box.checked; };
  box.addEventListener("change", sync); sync();
  document.getElementById("scanForm").addEventListener("submit", () => { btn.textContent = "Scanning..."; });
});
