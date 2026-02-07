const copyValue = async (id) => {
  const field = document.getElementById(id);
  if (!field) return;
  const value = field.value || field.textContent || "";
  await navigator.clipboard.writeText(value);
};

const toggleSecret = (id) => {
  const field = document.getElementById(id);
  if (!field) return;
  field.type = field.type === "password" ? "text" : "password";
};

document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", () => copyValue(btn.dataset.copy));
});

document.querySelectorAll("[data-toggle]").forEach((btn) => {
  btn.addEventListener("click", () => toggleSecret(btn.dataset.toggle));
});

const generateButtons = document.querySelectorAll("[data-generate]");
generateButtons.forEach((btn) => {
  btn.addEventListener("click", async () => {
    const length = document.getElementById("gen-length")?.value || 16;
    const digits = document.getElementById("gen-digits")?.checked ? 1 : 0;
    const symbols = document.getElementById("gen-symbols")?.checked ? 1 : 0;
    const target = btn.dataset.target || "gen-output";

    const response = await fetch(
      `/api/generate-password?length=${length}&digits=${digits}&symbols=${symbols}`
    );
    const data = await response.json();
    const output = document.getElementById(target);
    if (output) {
      output.value = data.password;
      output.focus();
      output.select();
    }
  });
});
