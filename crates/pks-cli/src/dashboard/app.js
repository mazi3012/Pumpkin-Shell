// Pumpkin-Shell Watch. Polls /api/snapshot every 2 seconds and draws it.
//
// Every value from the logs goes into the page with textContent or as element
// text. Nothing from a log is ever parsed as HTML, because a target can
// contain anything the sandbox wrote.
(function () {
  "use strict";

  var POLL_MS = 2000;
  var STALE_MS = 6000;
  var lastOk = 0;

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clock(ms) {
    var d = new Date(ms);
    var pad = function (n) { return (n < 10 ? "0" : "") + n; };
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function shortId(id) { return id ? id.slice(0, 8) : ""; }

  var SEVERITY_LABEL = { critical: "Critical", high: "High", warn: "Warn", notice: "Notice" };

  function renderTotals(t) {
    $("t-running").textContent = t.running;
    $("t-findings").textContent = t.findings;
    $("t-critical").textContent = t.critical;
    $("t-high").textContent = t.high;
    $("t-decoy").textContent = t.decoy_reads;
    $("t-net").textContent = t.network_blocked;
    $("t-reg").textContent = t.registry_refused;
    $("t-mon").textContent = t.monitor_events;
  }

  function renderAlert(t, snap) {
    var box = $("alert");
    if (t.critical > 0) {
      box.hidden = false;
      $("alert-title").textContent = t.critical + " critical finding" + (t.critical === 1 ? "" : "s") + ".";
      var newest = null;
      for (var i = 0; i < snap.events.length; i++) {
        if (snap.events[i].severity === "critical") { newest = snap.events[i]; break; }
      }
      $("alert-body").textContent = newest
        ? "Latest: " + newest.rule + " on " + newest.target + ". Use the terminal to review or kill the session."
        : "Use the terminal to review or kill the session.";
    } else {
      box.hidden = true;
    }
  }

  function renderChain(t, sessions) {
    // Unclosed logs are intact, so they do not count as failures.
    var pill = $("chain");
    var verified = 0;
    for (var i = 0; i < sessions.length; i++) {
      var c = sessions[i].check;
      if (c === "verified" || c === "open" || c === "unclosed") { verified++; }
    }
    if (t.logs_failed > 0) {
      pill.className = "pill bad";
      pill.textContent = t.logs_failed + " log" + (t.logs_failed === 1 ? "" : "s") + " failed the check";
    } else {
      pill.className = "pill ok";
      pill.textContent = "All logs intact (" + verified + ")";
    }
  }

  function renderFeed(events) {
    var list = $("feed");
    list.textContent = "";
    $("feed-empty").hidden = events.length > 0;
    $("feed-count").textContent = events.length ? "newest first, " + events.length + " shown" : "";
    events.forEach(function (ev) {
      var li = el("li");
      var sev = el("span", "sev " + ev.severity, SEVERITY_LABEL[ev.severity] || ev.severity);
      var main = el("div", "ev-main");
      main.appendChild(el("div", "ev-rule", ev.rule));
      main.appendChild(el("div", "ev-target", ev.target));
      var meta = el("div", "ev-meta");
      meta.appendChild(el("span", "chip", ev.layer));
      meta.appendChild(el("span", "chip", shortId(ev.session)));
      meta.appendChild(el("span", null, clock(ev.ts) + " · " + ev.verdict));
      main.appendChild(meta);
      li.appendChild(sev);
      li.appendChild(main);
      list.appendChild(li);
    });
  }

  function renderSessions(sessions) {
    var list = $("sessions");
    list.textContent = "";
    $("sessions-empty").hidden = sessions.length > 0;
    $("session-count").textContent = sessions.length ? sessions.length + " total" : "";
    sessions.forEach(function (s) {
      var li = el("li", "session");
      var head = el("header");
      head.appendChild(el("span", "id", shortId(s.id)));
      head.appendChild(el("span", "state " + s.status, s.status));
      li.appendChild(head);
      li.appendChild(el("div", "repo", s.repo || "(no repo recorded)"));
      var meta = el("div", "meta");
      meta.appendChild(el("span", null, s.entries + " records · " + s.findings + " findings · "));
      meta.appendChild(el("span", "check " + s.check, "log: " + s.check));
      meta.appendChild(el("span", null, s.started ? " · started " + clock(s.started) : ""));
      li.appendChild(meta);
      list.appendChild(li);
    });
  }

  function renderBars(id, items, max) {
    var list = $(id);
    list.textContent = "";
    if (items.length === 0) {
      list.appendChild(el("li", "empty", "Nothing recorded yet."));
      return;
    }
    items.slice(0, 8).forEach(function (item) {
      var li = el("li");
      li.appendChild(el("span", "name", item.name));
      li.appendChild(el("span", "n", item.count));
      var bar = el("div", "bar");
      var fill = el("i");
      fill.style.width = Math.max(4, Math.round((item.count / max) * 100)) + "%";
      bar.appendChild(fill);
      li.appendChild(bar);
      list.appendChild(li);
    });
  }

  function render(snap) {
    renderTotals(snap.totals);
    renderAlert(snap.totals, snap);
    renderChain(snap.totals, snap.sessions);
    renderFeed(snap.events);
    renderSessions(snap.sessions);
    var topRule = snap.by_rule.length ? snap.by_rule[0].count : 1;
    var topLayer = snap.by_layer.length ? snap.by_layer[0].count : 1;
    renderBars("rules", snap.by_rule, topRule);
    renderBars("layers", snap.by_layer, topLayer);
    $("updated").textContent = "updated " + clock(snap.generated * 1 || Date.now());
  }

  function setLive(ok) {
    var pill = $("live");
    if (ok) {
      pill.className = "pill live";
      $("live-text").textContent = "Live";
    } else {
      pill.className = "pill live stale";
      $("live-text").textContent = "Reconnecting";
    }
  }

  function poll() {
    fetch("/api/snapshot", { cache: "no-store", credentials: "omit" })
      .then(function (res) {
        if (!res.ok) { throw new Error("HTTP " + res.status); }
        return res.json();
      })
      .then(function (snap) {
        lastOk = Date.now();
        setLive(true);
        render(snap);
      })
      .catch(function () {
        if (Date.now() - lastOk > STALE_MS) { setLive(false); }
      })
      .then(function () {
        window.setTimeout(poll, POLL_MS);
      });
  }

  poll();
})();
