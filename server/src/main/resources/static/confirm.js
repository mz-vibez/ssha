// Forms with data-confirm ask before submitting. (The CSP allows no inline onsubmit handlers.)
document.addEventListener("submit", (e) => {
    const message = e.target.dataset?.confirm;
    if (message && !confirm(message)) e.preventDefault();
});
