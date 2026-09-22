(() => {
  "use strict";

  const DOC_RE = /^(?:\.\/)?(?:STRATEGIES|SCORING|SNMP|tcp\/[\w.-]+|udp\/[\w.-]+)\.md$/i;

  const backdrop = document.getElementById("cga-backdrop");
  const pathEl = document.getElementById("cga-path");
  const bootEl = document.getElementById("cga-boot");
  const bodyEl = document.getElementById("cga-body");
  const statusEl = document.getElementById("cga-status-msg");
  const closeBtn = document.getElementById("cga-close");
  const rawBtn = document.getElementById("cga-raw");
  const screenEl = document.querySelector(".cga-screen");

  if (!backdrop || !pathEl || !bootEl || !bodyEl) return;

  let currentHref = "";
  const cache = new Map();

  function isDocHref(href) {
    if (!href) return false;
    try {
      const url = new URL(href, window.location.href);
      if (url.origin !== window.location.origin) return false;
      const base = window.location.pathname.replace(/[^/]*$/, "");
      let rel = url.pathname;
      if (rel.startsWith(base)) rel = rel.slice(base.length);
      rel = rel.replace(/^\//, "");
      return DOC_RE.test(rel);
    } catch {
      return false;
    }
  }

  function displayPath(href) {
    const clean = href.replace(/^\.\//, "");
    return `C:\\HPA\\DOCS\\${clean.replace(/\//g, "\\").toUpperCase()}`;
  }

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function rewriteHref(url, docHref) {
    if (!url || /^(https?:|mailto:|data:)/i.test(url) || url.startsWith("#")) return url;
    try {
      const abs = new URL(url, new URL(docHref, window.location.href));
      const pageDir = new URL("./", window.location.href);
      let rel = abs.pathname;
      if (rel.startsWith(pageDir.pathname)) {
        rel = rel.slice(pageDir.pathname.length);
      }
      return rel + abs.hash;
    } catch {
      return url;
    }
  }

  function inlineFormat(text, docHref) {
    let s = escapeHtml(text);
    s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, "$1<em>$2</em>");
    s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, url) => {
      const decoded = url.replace(/&amp;/g, "&");
      const href = escapeHtml(rewriteHref(decoded, docHref));
      const cls = isDocHref(href.replace(/&amp;/g, "&")) ? ' class="term-doc"' : "";
      const target = /^https?:\/\//i.test(decoded) ? ' target="_blank" rel="noopener"' : "";
      return `<a href="${href}"${cls}${target}>${label}</a>`;
    });
    return s;
  }

  function isTableSep(line) {
    return /^\|?[\s:-]+\|[\s|:-]*$/.test(line.trim());
  }

  function splitRow(line) {
    let s = line.trim();
    if (s.startsWith("|")) s = s.slice(1);
    if (s.endsWith("|")) s = s.slice(0, -1);
    return s.split("|").map((c) => c.trim());
  }

  function renderTable(rows, docHref) {
    if (!rows.length) return "";
    const head = rows[0];
    const body = rows.slice(1);
    let html = "<table><thead><tr>";
    for (const cell of head) html += `<th>${inlineFormat(cell, docHref)}</th>`;
    html += "</tr></thead><tbody>";
    for (const row of body) {
      html += "<tr>";
      for (let i = 0; i < head.length; i++) {
        html += `<td>${inlineFormat(row[i] || "", docHref)}</td>`;
      }
      html += "</tr>";
    }
    html += "</tbody></table>";
    return html;
  }

  function mdToHtml(md, docHref) {
    const lines = md.replace(/\r\n/g, "\n").split("\n");
    const out = [];
    let i = 0;
    let inFence = false;
    let fence = [];
    let para = [];
    let listType = null;
    let listItems = [];
    let tableRows = null;

    const flushPara = () => {
      if (!para.length) return;
      out.push(`<p>${inlineFormat(para.join(" "), docHref)}</p>`);
      para = [];
    };

    const flushList = () => {
      if (!listType) return;
      const tag = listType;
      out.push(
        `<${tag}>${listItems.map((item) => `<li>${inlineFormat(item, docHref)}</li>`).join("")}</${tag}>`
      );
      listType = null;
      listItems = [];
    };

    const flushTable = () => {
      if (!tableRows) return;
      out.push(renderTable(tableRows, docHref));
      tableRows = null;
    };

    while (i < lines.length) {
      const line = lines[i];

      if (inFence) {
        if (/^```/.test(line)) {
          out.push(`<pre><code>${escapeHtml(fence.join("\n"))}</code></pre>`);
          inFence = false;
          fence = [];
        } else {
          fence.push(line);
        }
        i += 1;
        continue;
      }

      if (/^```/.test(line)) {
        flushPara();
        flushList();
        flushTable();
        inFence = true;
        fence = [];
        i += 1;
        continue;
      }

      if (
        /^\|.+\|/.test(line.trim()) ||
        (line.includes("|") && i + 1 < lines.length && isTableSep(lines[i + 1]))
      ) {
        flushPara();
        flushList();
        if (!tableRows) tableRows = [];
        if (!isTableSep(line)) tableRows.push(splitRow(line));
        i += 1;
        continue;
      }

      if (tableRows && !line.includes("|")) flushTable();

      if (/^\s*$/.test(line)) {
        flushPara();
        flushList();
        flushTable();
        i += 1;
        continue;
      }

      if (/^---+$/.test(line.trim()) || /^\*\*\*+$/.test(line.trim())) {
        flushPara();
        flushList();
        flushTable();
        out.push("<hr>");
        i += 1;
        continue;
      }

      const heading = line.match(/^(#{1,4})\s+(.*)$/);
      if (heading) {
        flushPara();
        flushList();
        flushTable();
        const level = heading[1].length;
        out.push(`<h${level}>${inlineFormat(heading[2], docHref)}</h${level}>`);
        i += 1;
        continue;
      }

      const ul = line.match(/^\s*[-*+]\s+(.*)$/);
      if (ul) {
        flushPara();
        flushTable();
        if (listType && listType !== "ul") flushList();
        listType = "ul";
        listItems.push(ul[1]);
        i += 1;
        continue;
      }

      const ol = line.match(/^\s*\d+\.\s+(.*)$/);
      if (ol) {
        flushPara();
        flushTable();
        if (listType && listType !== "ol") flushList();
        listType = "ol";
        listItems.push(ol[1]);
        i += 1;
        continue;
      }

      const bq = line.match(/^>\s?(.*)$/);
      if (bq) {
        flushPara();
        flushList();
        flushTable();
        out.push(`<blockquote>${inlineFormat(bq[1], docHref)}</blockquote>`);
        i += 1;
        continue;
      }

      flushList();
      flushTable();
      para.push(line.trim());
      i += 1;
    }

    flushPara();
    flushList();
    flushTable();
    if (inFence) out.push(`<pre><code>${escapeHtml(fence.join("\n"))}</code></pre>`);
    return out.join("\n");
  }

  function setBoot(path, state) {
    const lines = [
      "IBM PC CGA — HONEYPOT-AUDITOR DOC VIEWER v1.0",
      "Copyright (C) 1981–2026  —  authorized BBS nodes only",
      "",
      `A> TYPE ${path}`,
    ];
    if (state === "loading") lines.push("Reading sectors...");
    else if (state === "ok") {
      lines.push('<span class="ok">OK</span>');
      lines.push("");
    } else if (state === "err") {
      lines.push("I/O ERROR — FILE NOT FOUND");
      lines.push("");
    }
    bootEl.innerHTML = lines.join("\n");
  }

  function openModal() {
    backdrop.classList.add("is-open");
    backdrop.setAttribute("aria-hidden", "false");
    document.body.classList.add("cga-lock");
    closeBtn?.focus();
  }

  function closeModal() {
    backdrop.classList.remove("is-open");
    backdrop.setAttribute("aria-hidden", "true");
    document.body.classList.remove("cga-lock");
    bodyEl.innerHTML = "";
    currentHref = "";
    if (window.location.hash.startsWith("#doc=")) {
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }

  async function loadDoc(href) {
    currentHref = href;
    const path = displayPath(href);
    pathEl.textContent = path;
    setBoot(path, "loading");
    bodyEl.innerHTML = "";
    if (statusEl) statusEl.textContent = "LOADING";
    openModal();
    if (screenEl) screenEl.scrollTop = 0;

    try {
      let md = cache.get(href);
      if (!md) {
        const res = await fetch(href, { credentials: "same-origin" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        md = await res.text();
        cache.set(href, md);
      }
      setBoot(path, "ok");
      bodyEl.innerHTML = mdToHtml(md, href);
      if (statusEl) statusEl.textContent = `${md.split("\n").length} LINES`;
      const hash = `#doc=${encodeURIComponent(href.replace(/^\.\//, ""))}`;
      if (window.location.hash !== hash) history.replaceState(null, "", hash);
    } catch (err) {
      setBoot(path, "err");
      bodyEl.innerHTML = `<p>${escapeHtml(String(err.message || err))}</p>
        <p>Try the raw file: <a href="${escapeHtml(href)}" target="_blank" rel="noopener">${escapeHtml(href)}</a></p>`;
      if (statusEl) statusEl.textContent = "ERROR";
    }
  }

  function resolveClick(event) {
    const a = event.target.closest("a");
    if (!a || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (a.target === "_blank") return;
    const hrefAttr = a.getAttribute("href");
    if (!hrefAttr || hrefAttr.startsWith("#") || hrefAttr.startsWith("mailto:")) return;
    const href = hrefAttr.split("#")[0];
    if (!/\.md$/i.test(href)) return;
    if (!a.classList.contains("term-doc") && !isDocHref(href)) return;
    event.preventDefault();
    loadDoc(href);
  }

  document.addEventListener("click", resolveClick);

  backdrop.addEventListener("click", (event) => {
    if (event.target === backdrop) closeModal();
  });

  closeBtn?.addEventListener("click", closeModal);

  rawBtn?.addEventListener("click", () => {
    if (currentHref) window.open(currentHref, "_blank", "noopener");
  });

  document.addEventListener("keydown", (event) => {
    if (!backdrop.classList.contains("is-open")) return;
    if (event.key === "Escape") {
      event.preventDefault();
      closeModal();
    }
  });

  const hash = window.location.hash;
  if (hash.startsWith("#doc=")) {
    const href = decodeURIComponent(hash.slice(5));
    if (href) loadDoc(href);
  }
})();
