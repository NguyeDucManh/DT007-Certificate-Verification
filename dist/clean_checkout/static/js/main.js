"use strict";
document.querySelectorAll('.batch-form').forEach((batchForm) => {
  batchForm.addEventListener('submit', (event) => {
    const button = batchForm.querySelector('button');
    if (button.disabled) { event.preventDefault(); return; }
    button.disabled = true;
    batchForm.querySelector('.batch-progress').hidden = false;
  });
  window.addEventListener('pageshow', () => {
    batchForm.querySelector('button').disabled = false;
    batchForm.querySelector('.batch-progress').hidden = true;
  });
});
document.querySelectorAll('.batch-detail-link').forEach((link) => {
  link.addEventListener('click', () => {
    const details = document.getElementById(link.hash.slice(1));
    if (details) details.open = true;
  });
});
const exportBatch = document.getElementById('export-batch');
if (exportBatch) exportBatch.addEventListener('click', () => {
  const csv = JSON.parse(document.getElementById('batch-csv').textContent);
  const url = URL.createObjectURL(new Blob(['\uFEFF', csv], {type:'text/csv;charset=utf-8'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'DT007-kiem-thu-tong-hop.csv';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
const demoForm = document.getElementById("demo-form");
if (demoForm) {
  demoForm.addEventListener("submit", (event) => {
    const button = document.getElementById("demo-button");
    if (button.disabled) { event.preventDefault(); return; }
    button.disabled = true;
    document.getElementById("demo-progress").hidden = false;
  });
  window.addEventListener("pageshow", () => {
    document.getElementById("demo-button").disabled = false;
    document.getElementById("demo-progress").hidden = true;
  });
}

const form = document.getElementById("scan-form");
if (form) {
  const input = document.getElementById("hostname");
  const button = document.getElementById("scan-button");
  const label = document.getElementById("button-label");
  const error = document.getElementById("client-error");
  const progress = document.getElementById("scan-progress");
  const spinner = document.getElementById("scan-spinner");
  form.addEventListener("submit", (event) => {
    if (button.disabled) {
      event.preventDefault();
      return;
    }
    // Server dùng validator đầy đủ của engine; kiểm tra nhanh này chỉ hỗ trợ UX.
    if (!input.value || /\s/.test(input.value) || /^https?:\/\//i.test(input.value)) {
      event.preventDefault();
      error.textContent = "Tên miền không hợp lệ. Vui lòng nhập dạng google.com, không kèm URL hoặc khoảng trắng.";
      error.hidden = false;
      input.setAttribute("aria-invalid", "true");
      input.focus();
      return;
    }
    error.hidden = true;
    input.removeAttribute("aria-invalid");
    form.setAttribute("aria-busy", "true");
    button.disabled = true;
    label.textContent = "Đang kiểm tra...";
    spinner.hidden = false;
    progress.hidden = false;
  });
  window.addEventListener("pageshow", () => {
    button.disabled = false;
    label.textContent = "KIỂM TRA CHỨNG THƯ";
    form.removeAttribute("aria-busy");
    progress.hidden = true;
    spinner.hidden = true;
  });
}

// Mỗi lần chỉ mở một SCT, kể cả trình duyệt chưa hỗ trợ details[name].
document.querySelectorAll(".sct-accordion").forEach((item) => {
  item.addEventListener("toggle", () => {
    if (item.open) {
      document.querySelectorAll(".sct-accordion").forEach((other) => {
        if (other !== item) other.open = false;
      });
    }
  });
});
