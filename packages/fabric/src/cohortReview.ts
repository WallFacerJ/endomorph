/**
 * A cohort review tool that needs no server.
 *
 * The product has no accounts and no backend, which normally rules out the
 * one thing an instructor most needs: seeing thirty results side by side.
 * But every run already exports a structured record, so the collection
 * problem can be solved with paste.
 *
 * This emits a self-contained page an instructor opens once and keeps.
 * Records go in, a comparison comes out. Nothing is uploaded, which also
 * means it can be used on results from analysts whose scores nobody wants
 * sitting on a third-party service.
 *
 * The question it exists to answer is not "who scored highest" -- a
 * spreadsheet does that. It is "which question did the cohort collectively
 * miss", because that names a teaching gap rather than a person, and it is
 * the reading an instructor can actually act on.
 */

export function renderCohortReview(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Endomorph cohort review</title>
<style>
  :root {
    color-scheme: light;
    --ink: #12181f;
    --muted: #5a6a7a;
    --line: #d8e0e8;
    --panel: #f6f8fa;
    --good: #1a7f4b;
    --bad: #b3261e;
    --warn: #a1670a;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 40px 28px 80px; background: #fff; color: var(--ink);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main { max-width: 1080px; margin: 0 auto; }
  h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: -0.02em; }
  h2 { margin: 36px 0 6px; font-size: 17px; }
  p { margin: 6px 0 0; }
  .lede { max-width: 72ch; color: var(--muted); }
  textarea {
    width: 100%; margin-top: 16px; padding: 12px; min-height: 150px;
    border: 1px solid var(--line); border-radius: 10px; background: var(--panel);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12.5px; line-height: 1.5; resize: vertical;
  }
  .row { display: flex; gap: 10px; align-items: center; margin-top: 12px; flex-wrap: wrap; }
  button {
    padding: 9px 16px; border: 1px solid var(--line); border-radius: 8px;
    background: var(--ink); color: #fff; font: inherit; font-size: 14px; cursor: pointer;
  }
  button.secondary { background: #fff; color: var(--ink); }
  .status { color: var(--muted); font-size: 13px; }
  .status.error { color: var(--bad); }
  table { width: 100%; border-collapse: collapse; margin-top: 14px; font-size: 13px; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--line); vertical-align: top; }
  thead th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .bar { display: inline-block; width: 110px; height: 7px; border-radius: 4px;
         background: var(--line); overflow: hidden; vertical-align: middle; }
  .bar span { display: block; height: 100%; background: var(--good); }
  .bar.low span { background: var(--bad); }
  .bar.mid span { background: var(--warn); }
  .warn { margin-top: 14px; padding: 12px 14px; border: 1px solid var(--line);
          border-left: 4px solid var(--warn); border-radius: 8px; background: #fffaf2;
          font-size: 13.5px; }
  .empty { margin-top: 16px; color: var(--muted); font-size: 14px; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.9em; }
  footer { margin-top: 56px; padding-top: 16px; border-top: 1px solid var(--line);
           color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<main>
  <h1>Cohort review</h1>
  <p class="lede">
    Paste the assessment records your analysts exported &mdash; one JSON object per line,
    or a JSON array. Nothing is uploaded; this page reads what you paste and nothing else.
  </p>

  <textarea id="input" spellcheck="false" placeholder='{"format":"endomorph-assessment", ...}'></textarea>

  <div class="row">
    <button id="run">Review</button>
    <button id="clear" class="secondary">Clear</button>
    <span class="status" id="status"></span>
  </div>

  <div id="output"></div>

  <footer>
    Endomorph cohort review. Results are only comparable when they share a scenario,
    a seed and an assistance level &mdash; this page says so rather than assuming it.
  </footer>
</main>

<script>
(function () {
  var input = document.getElementById("input");
  var output = document.getElementById("output");
  var status = document.getElementById("status");

  function esc(value) {
    return String(value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  /*
    Accepts a JSON array or one object per line, because both are what people
    actually end up with: a paste from a spreadsheet column, or several
    copies appended one after another.
  */
  function parseRecords(text) {
    var trimmed = text.trim();
    if (!trimmed) return { records: [], errors: [] };

    try {
      var asArray = JSON.parse(trimmed);
      if (Array.isArray(asArray)) return { records: asArray, errors: [] };
      return { records: [asArray], errors: [] };
    } catch (ignored) { /* fall through to line mode */ }

    var records = [];
    var errors = [];
    trimmed.split(/\\r?\\n/).forEach(function (line, index) {
      var value = line.trim();
      if (!value) return;
      try { records.push(JSON.parse(value)); }
      catch (error) { errors.push("Line " + (index + 1) + " is not valid JSON."); }
    });
    return { records: records, errors: errors };
  }

  function pct(earned, available) {
    return available > 0 ? Math.round((earned / available) * 100) : 0;
  }

  function barClass(value) {
    return value >= 70 ? "" : value >= 40 ? " mid" : " low";
  }

  function render(records, parseErrors) {
    var valid = records.filter(function (record) {
      return record && record.format === "endomorph-assessment";
    });

    if (valid.length === 0) {
      output.innerHTML = '<p class="empty">No assessment records found. ' +
        'Each one begins <code>{"format":"endomorph-assessment"</code>.</p>';
      status.className = "status error";
      status.textContent = parseErrors.length
        ? parseErrors.join(" ")
        : "Nothing recognisable pasted.";
      return;
    }

    status.className = "status";
    status.textContent = valid.length + " record(s) read." +
      (parseErrors.length ? " " + parseErrors.length + " line(s) skipped." : "");

    var html = "";

    /*
      Comparability first, before any number is shown. Two results from
      different scenarios, seeds or assistance levels are not a cohort, and
      putting them in one table invites exactly the comparison that is not
      valid.
    */
    var scenarios = {}, seeds = {}, modes = {};
    valid.forEach(function (record) {
      scenarios[record.scenario && record.scenario.id] = true;
      seeds[record.reproducibility && record.reproducibility.seed] = true;
      modes[record.assistance] = true;
    });

    var mixed = [];
    if (Object.keys(scenarios).length > 1) mixed.push("more than one scenario");
    if (Object.keys(seeds).length > 1) mixed.push("more than one seed");
    if (Object.keys(modes).length > 1) mixed.push("more than one assistance level");

    if (mixed.length) {
      var listed = mixed.length > 1
        ? mixed.slice(0, -1).join(", ") + " and " + mixed[mixed.length - 1]
        : mixed[0];

      html += '<div class="warn"><strong>These results are not directly comparable.</strong> ' +
        'They come from ' + esc(listed) +
        '. Scores only mean the same thing when the telemetry and the amount of help did.</div>';
    }

    html += "<h2>Results</h2>";
    html += '<table><thead><tr><th>Result</th><th>Assistance</th><th>Outcome</th>' +
      '<th class="num">Questions</th><th>&nbsp;</th><th class="num">Evidence</th></tr></thead><tbody>';

    valid.slice().sort(function (a, b) {
      return pct(b.questions.earned, b.questions.available) -
        pct(a.questions.earned, a.questions.available);
    }).forEach(function (record, index) {
      var score = pct(record.questions.earned, record.questions.available);
      html += "<tr>" +
        "<th scope=\\"row\\">" + esc(record.label || ("Result " + (index + 1))) + "</th>" +
        "<td>" + esc(record.assistance) + "</td>" +
        "<td>" + esc(record.completed ? record.outcome.status : "not finalized") + "</td>" +
        '<td class="num">' + record.questions.earned + "/" + record.questions.available + "</td>" +
        '<td><span class="bar' + barClass(score) + '"><span style="width:' + score + '%"></span></span></td>' +
        '<td class="num">' + (record.work ? record.work.evidenceCollected : 0) + "</td>" +
        "</tr>";
    });
    html += "</tbody></table>";

    /*
      The reading an instructor can act on. "Who scored highest" is a
      spreadsheet; "which question did most of the cohort miss" names a
      teaching gap rather than a person.
    */
    var byQuestion = {};
    valid.forEach(function (record) {
      (record.questions.results || []).forEach(function (result) {
        var entry = byQuestion[result.id] ||
          (byQuestion[result.id] = { prompt: result.prompt, correct: 0, total: 0 });
        entry.total += 1;
        if (result.correct) entry.correct += 1;
      });
    });

    var questions = Object.keys(byQuestion).map(function (id) {
      var entry = byQuestion[id];
      return { id: id, prompt: entry.prompt, correct: entry.correct, total: entry.total,
               rate: entry.total ? Math.round((entry.correct / entry.total) * 100) : 0 };
    }).sort(function (a, b) { return a.rate - b.rate; });

    if (questions.length) {
      html += "<h2>Where the cohort struggled</h2>";
      html += '<p class="lede">Lowest first. A question most of the group missed is a gap in ' +
        'the teaching before it is a gap in the analysts.</p>';
      html += '<table><thead><tr><th>Question</th><th class="num">Correct</th>' +
        '<th>&nbsp;</th></tr></thead><tbody>';
      questions.forEach(function (question) {
        html += "<tr><th scope=\\"row\\">" + esc(question.prompt) + "</th>" +
          '<td class="num">' + question.correct + "/" + question.total + "</td>" +
          '<td><span class="bar' + barClass(question.rate) + '"><span style="width:' +
          question.rate + '%"></span></span></td></tr>';
      });
      html += "</tbody></table>";
    }

    output.innerHTML = html;
  }

  document.getElementById("run").addEventListener("click", function () {
    var parsed = parseRecords(input.value);
    render(parsed.records, parsed.errors);
  });

  document.getElementById("clear").addEventListener("click", function () {
    input.value = "";
    output.innerHTML = "";
    status.textContent = "";
    status.className = "status";
  });
})();
</script>
</body>
</html>
`;
}
