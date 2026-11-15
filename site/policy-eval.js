/* TARA policy engine — faithful browser port of tara/core.py Policy.evaluate().
 * Verified against the real Python engine (40/40 vectors). No network, no state.
 * Mirrors: norm_path, fnmatch/fnmatchcase, canonical(JSON), protected paths/shell,
 * first-match-wins rules (tools / paths / command_regex / input_regex), and the default. */
(function (root) {
  "use strict";
  var PATH_KEYS = ["file_path", "notebook_path", "path"];
  var SHELL_TOOLS = ["Bash", "PowerShell"];
  var HOME = "/home/you"; // '~' expands here (matches the verification harness)

  function expanduser(p) {
    if (p === "~") return HOME;
    if (p.indexOf("~/") === 0 || p.indexOf("~\\") === 0) return HOME + "/" + p.slice(2);
    return p;
  }
  function expandvars(p) {
    return p.replace(/%USERPROFILE%/gi, HOME).replace(/\$HOME\b/g, HOME).replace(/%HOME%/gi, HOME);
  }
  function isAbs(p) { return /^[\\/]/.test(p) || /^[a-zA-Z]:[\\/]/.test(p); }
  function normpath(p) {
    var s = p.replace(/\\/g, "/");
    var absolute = s.charAt(0) === "/";
    var drive = (s.match(/^[a-zA-Z]:/) || [""])[0];
    if (drive) s = s.slice(drive.length);
    var parts = s.split("/"), out = [], i, seg;
    for (i = 0; i < parts.length; i++) {
      seg = parts[i];
      if (seg === "" || seg === ".") continue;
      if (seg === "..") {
        if (out.length && out[out.length - 1] !== "..") out.pop();
        else if (!absolute && !drive) out.push("..");
      } else out.push(seg);
    }
    var res = out.join("/");
    if (absolute || drive) res = drive + "/" + res;
    res = res.replace(/\/+$/, "");
    return res || (absolute || drive ? drive + "/" : ".");
  }
  function normPath(p, cwd) {
    p = expandvars(expanduser(String(p)));
    if (cwd && !isAbs(p)) p = cwd.replace(/\/+$/, "") + "/" + p;
    return normpath(p).replace(/\\/g, "/").toLowerCase();
  }

  function translate(pat) {
    var i = 0, n = pat.length, res = "", c, j, stuff;
    while (i < n) {
      c = pat[i++];
      if (c === "*") res += ".*";
      else if (c === "?") res += ".";
      else if (c === "[") {
        j = i;
        if (j < n && (pat[j] === "!" || pat[j] === "^")) j++;
        if (j < n && pat[j] === "]") j++;
        while (j < n && pat[j] !== "]") j++;
        if (j >= n) { res += "\\["; }
        else {
          stuff = pat.slice(i, j).replace(/\\/g, "\\\\");
          i = j + 1;
          if (stuff.charAt(0) === "!") stuff = "^" + stuff.slice(1);
          res += "[" + stuff + "]";
        }
      } else res += c.replace(/[.^$+{}()|\\\/\[\]]/g, "\\$&");
    }
    return "^(?:" + res + ")$";
  }
  function fnmatchcase(name, pat) { return new RegExp(translate(pat)).test(name); }
  var fnmatch = fnmatchcase; // paths are pre-lowercased by normPath

  function canonical(obj) {
    if (obj === null) return "null";
    if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
    if (typeof obj === "object") {
      return "{" + Object.keys(obj).sort().map(function (k) {
        return JSON.stringify(k) + ":" + canonical(obj[k]);
      }).join(",") + "}";
    }
    return JSON.stringify(obj);
  }

  function pyRegex(src) {
    var flags = "";
    if (src.indexOf("(?i)") === 0) { flags = "i"; src = src.slice(4); }
    return new RegExp(src, flags);
  }

  function createPolicy(doc) {
    var def = doc.default || "approve";
    var levels = Object.assign(
      { low: "code", medium: "code", high: "code", critical: "two_person" },
      doc.approval_levels || {}
    );
    var protectedPaths = (doc.protected_paths || []).map(function (p) { return normPath(p); });
    var protectedShell = (doc.protected_shell_patterns || []).map(function (p) { return new RegExp(p, "i"); });
    var rules = (doc.rules || []).map(function (r) {
      var o = Object.assign({}, r);
      o._paths = (r.paths || []).map(function (p) { return normPath(p); });
      o._re = r.command_regex ? pyRegex(r.command_regex) : null;
      o._input_re = r.input_regex ? pyRegex(r.input_regex) : null;
      return o;
    });

    function isProtected(p) {
      return protectedPaths.some(function (g) { return fnmatch(p, g) || p === g.replace(/[/*]+$/, ""); });
    }

    function evaluate(toolName, toolInput, cwd) {
      toolInput = toolInput || {};
      var paths = [], k, i;
      for (i = 0; i < PATH_KEYS.length; i++) { k = PATH_KEYS[i]; if (toolInput[k]) paths.push(normPath(toolInput[k], cwd)); }
      var pattern = toolInput.pattern;
      if (toolName === "Glob" && pattern && isAbs(expanduser(String(pattern)))) paths.push(normPath(pattern));
      if (!paths.length && ["Glob", "Grep", "LS"].indexOf(toolName) !== -1 && cwd) paths.push(normPath(cwd));
      var command = SHELL_TOOLS.indexOf(toolName) !== -1 ? String(toolInput.command || "") : "";
      var commandNorm = command.replace(/\\/g, "/");

      if (paths.some(isProtected)) return { decision: "deny", rule: "protected path", risk: "critical" };
      if (command && protectedShell.some(function (rx) { return rx.test(commandNorm); }))
        return { decision: "deny", rule: "protected resource in shell command", risk: "critical" };

      for (i = 0; i < rules.length; i++) {
        var r = rules[i];
        if (!(r.tools || []).some(function (t) { return fnmatchcase(toolName, t); })) continue;
        if (r._paths.length && !(paths.length && paths.every(function (p) {
          return r._paths.some(function (g) { return fnmatch(p, g); });
        }))) continue;
        if (r._re && !r._re.test(command)) continue;
        if (r._input_re && !r._input_re.test(canonical(toolInput))) continue;
        var risk = r.risk || (r.decision === "approve" ? "medium" : "low");
        return { decision: r.decision, rule: r.name, risk: risk };
      }
      return { decision: def, rule: "default (unlisted action)", risk: "medium" };
    }

    function levelForRisk(risk) { return levels[risk] || "code"; }
    return { evaluate: evaluate, levelForRisk: levelForRisk, levels: levels };
  }

  var API = { createPolicy: createPolicy, normPath: normPath, fnmatchcase: fnmatchcase, canonical: canonical };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  if (root) root.TARAEval = API;
})(typeof window !== "undefined" ? window : null);
