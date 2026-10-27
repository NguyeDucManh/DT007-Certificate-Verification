"use strict";

document.documentElement.classList.add("js");
const navToggle = document.querySelector(".nav-toggle");
const navigation = document.getElementById("main-nav");
if (navToggle && navigation) {
  const closeNavigation = () => {
    navigation.classList.remove("is-open");
    navToggle.setAttribute("aria-expanded", "false");
  };
  navToggle.addEventListener("click", () => {
    const open = navigation.classList.toggle("is-open");
    navToggle.setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && navigation.classList.contains("is-open")) {
      closeNavigation();
      navToggle.focus();
    }
  });
  navigation.querySelectorAll("a").forEach((link) => link.addEventListener("click", closeNavigation));
}

document.querySelectorAll(".case-form").forEach((caseForm) => {
  const button = caseForm.querySelector("button");
  const progress = caseForm.querySelector(".case-progress");
  caseForm.addEventListener("submit", (event) => {
    if (button.disabled) { event.preventDefault(); return; }
    button.disabled = true;
    progress.hidden = false;
    caseForm.setAttribute("aria-busy", "true");
  });
  window.addEventListener("pageshow", () => {
    button.disabled = false;
    progress.hidden = true;
    caseForm.removeAttribute("aria-busy");
  });
});

// Export the displayed snapshot; never trigger a second security scan.
function downloadSnapshot(data, type, name) {
  const url = URL.createObjectURL(new Blob([data], {type}));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const resultData = document.getElementById("result-data");
if (resultData) {
  document.querySelectorAll("[data-export]").forEach((button) => {
    button.addEventListener("click", async () => {
      const status = document.getElementById("export-status");
      button.disabled = true;
      try {
        const snapshot = JSON.parse(resultData.textContent);
        const name = "DT007-" + snapshot.hostname.replace(/[^a-zA-Z0-9.-]/g, "_");
        if (button.dataset.export === "json") {
          downloadSnapshot(JSON.stringify(snapshot, null, 2), "application/json;charset=utf-8", name + ".json");
        } else {
          const stylesheet = document.querySelector('link[rel="stylesheet"]');
          const response = await fetch(stylesheet.href);
          if (!response.ok) throw new Error("stylesheet unavailable");
          const css = await response.text();
          const page = document.documentElement.cloneNode(true);
          page.classList.remove("js");
          page.querySelectorAll('script, link[rel="stylesheet"], [data-export], .nav-toggle').forEach((node) => node.remove());
          page.querySelectorAll("details").forEach((node) => { node.open = true; node.removeAttribute("name"); });
          page.querySelector("#export-status").textContent = "Bản lưu của lần kiểm tra, không tự cập nhật dữ liệu.";
          const style = document.createElement("style");
          style.textContent = css;
          page.querySelector("head").appendChild(style);
          downloadSnapshot("<!doctype html>\n" + page.outerHTML, "text/html;charset=utf-8", name + ".html");
        }
        status.textContent = "Đã tạo tệp " + button.dataset.export.toUpperCase() + " từ kết quả hiện tại.";
      } catch {
        status.textContent = "Không thể xuất tệp. Vui lòng thử lại; kết quả kiểm tra vẫn được giữ trên trang.";
      } finally {
        button.disabled = false;
      }
    });
  });
}
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
