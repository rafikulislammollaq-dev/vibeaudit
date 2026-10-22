/**
 * app.core.js
 * ---------------------------------------------------------------------------
 * The browser app: file intake, progress, scanning and rendering.
 *
 * WHY this file has no `import` / `export`: the page has to work both when it
 * is served over http(s) and when it is opened straight from the filesystem
 * (file://), because browsers refuse to load ES modules over file://. The
 * logic lives in classic scripts that publish themselves on
 * `globalThis.SCANNER`; `app.js` is the thin ES-module entry point used when
 * the folder is served.
 *
 * PRIVACY: nothing in this file opens a network connection. Files are read
 * with the browser File API and analysed in memory. There is no fetch, no
 * XHR, no WebSocket, no analytics and no CDN.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.app = S.app || {};

  const state = {
    report: null,
    busy: false,
    lastLabel: 'the selected folder',
  };

  /* ------------------------------------------------------------------ */
  /* tiny DOM helpers                                                    */
  /* ------------------------------------------------------------------ */

  function el(id) {
    return document.getElementById(id);
  }

  function make(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined && value !== null) node.textContent = String(value);
    return node;
  }

  function clear(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function tick() {
    return new Promise((resolve) => setTimeout(resolve, 0));
  }

  /* ------------------------------------------------------------------ */
  /* status + progress                                                   */
  /* ------------------------------------------------------------------ */

  function setStatus(message, tone) {
    const node = el('status');
    if (!node) return;
    node.textContent = message || '';
    node.className = 'status' + (tone ? ` status-${tone}` : '');
  }

  function setProgress(done, total, label) {
    const bar = el('progress-bar');
    const textNode = el('progress-text');
    const wrap = el('progress');
    const track = wrap && wrap.querySelector ? wrap.querySelector('.progress-track') : null;
    if (!bar || !textNode || !wrap) return;
    const pct = total ? Math.round((done / total) * 100) : 0;
    bar.style.width = `${pct}%`;
    if (track && track.setAttribute) track.setAttribute('aria-valuenow', String(pct));
    textNode.textContent = label || `${done} of ${total} files read (${pct}%)`;
    wrap.hidden = false;
  }

  function hideProgress() {
    const wrap = el('progress');
    if (wrap) wrap.hidden = true;
  }

  /* ------------------------------------------------------------------ */
  /* file intake                                                         */
  /* ------------------------------------------------------------------ */

  /** Should this path be skipped outright? */
  function shouldSkipPath(relPath) {
    const segments = String(relPath).split('/');
    for (const segment of segments) {
      if (S.lib.files.SKIP_DIRS.has(segment)) return true;
    }
    return false;
  }

  /**
   * Turn one browser File into a file record (or null when it is skipped).
   */
  async function buildRecord(file, relPath) {
    const name = relPath.split('/').pop();
    const alwaysScan = S.lib.files.isAlwaysScanned(relPath, name);

    if (!alwaysScan && shouldSkipPath(relPath)) return { skipped: 'ignored folder' };
    if (file.size > S.lib.files.MAX_FILE_BYTES) return { skipped: 'too large' };

    const record = S.lib.files.createFileRecord({
      relPath,
      name,
      ext: name.includes('.') ? name.slice(name.lastIndexOf('.')) : '',
      size: file.size,
    });

    if (!S.lib.files.isTextLike(record)) return { skipped: 'not a text file' };

    let text = '';
    try {
      text = await file.text();
    } catch (error) {
      return { skipped: `could not be read (${String(error && error.message)})` };
    }
    if (S.lib.files.looksBinary(text)) return { skipped: 'binary file' };

    record.content = text;
    return { record };
  }

  /** Files chosen with the folder picker (`webkitdirectory`). */
  async function intakeFromInput(input) {
    const list = Array.from((input && input.files) || []);
    if (!list.length) return { entries: [], label: '' };

    const firstPath = list[0].webkitRelativePath || '';
    const rootName = firstPath.includes('/') ? firstPath.split('/')[0] : '';

    const entries = list.map((file) => {
      const raw = file.webkitRelativePath || file.name;
      const parts = raw.split('/');
      if (rootName && parts[0] === rootName) parts.shift();
      return { file, relPath: parts.join('/') || file.name };
    });

    return { entries, label: rootName || '' };
  }

  /**
   * Read a directory entry.
   *
   * WHY the loop: `readEntries()` returns at most 100 entries per call, so a
   * directory with 250 files needs three calls - and the browser only tells
   * you it is finished when it returns an EMPTY batch.
   */
  function readDirectory(reader) {
    return new Promise((resolve, reject) => {
      const all = [];
      const step = () => {
        reader.readEntries((batch) => {
          if (!batch || batch.length === 0) {
            resolve(all);
            return;
          }
          all.push(...batch);
          step();
        }, reject);
      };
      step();
    });
  }

  function fileFromEntry(entry) {
    return new Promise((resolve, reject) => {
      entry.file(resolve, reject);
    });
  }

  /**
   * Walk a dropped entry (file or directory) with the Directory Entries API.
   * Every failure is collected and reported to the user - a dropped folder
   * that cannot be read must never fail silently.
   */
  async function walkEntry(entry, prefix, out, errors) {
    try {
      if (entry.isFile) {
        const file = await fileFromEntry(entry);
        out.push({ file, relPath: `${prefix}${entry.name}` });
        return;
      }
      if (entry.isDirectory) {
        const reader = entry.createReader();
        const children = await readDirectory(reader);
        for (const child of children) {
          await walkEntry(child, `${prefix}${entry.name}/`, out, errors);
        }
        return;
      }
      errors.push(`"${entry.name}" is not a file or a folder, so it was skipped.`);
    } catch (error) {
      errors.push(`Could not read "${entry.name}": ${String((error && error.message) || error)}`);
    }
  }

  /** Files dropped onto the drop zone. */
  async function intakeFromDrop(dataTransfer) {
    const entries = [];
    const errors = [];
    const items = dataTransfer && dataTransfer.items ? Array.from(dataTransfer.items) : [];
    let label = '';

    let sawEntry = false;
    for (const item of items) {
      if (item.kind && item.kind !== 'file') continue;
      const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
      if (!entry) continue;
      sawEntry = true;

      const batch = [];
      await walkEntry(entry, '', batch, errors);

      // Dropping a folder should give the same relative paths as the folder
      // picker, so the folder's own name is stripped from the front.
      const strip = entry.isDirectory ? `${entry.name}/` : '';
      if (entry.isDirectory && !label) label = entry.name;
      for (const item2 of batch) {
        const relPath =
          strip && item2.relPath.startsWith(strip) ? item2.relPath.slice(strip.length) : item2.relPath;
        entries.push({ file: item2.file, relPath });
      }
    }

    if (!sawEntry) {
      // Older browsers (and some Firefox versions) do not implement the
      // directory entries API. Fall back to the plain file list, and say so.
      const files = dataTransfer && dataTransfer.files ? Array.from(dataTransfer.files) : [];
      for (const file of files) entries.push({ file, relPath: file.name });
      if (files.length) {
        errors.push(
          'This browser did not expose the dropped folder as a directory, so only the files it listed were ' +
            'scanned. Use the "Choose a folder" button for a complete scan.',
        );
      }
      return { entries, errors, label: '' };
    }

    return { entries, errors, label };
  }

  /* ------------------------------------------------------------------ */
  /* the scan                                                            */
  /* ------------------------------------------------------------------ */

  async function ingest(entries) {
    const files = [];
    const skipped = [];
    let bytes = 0;
    let done = 0;

    for (const entry of entries) {
      done += 1;
      const result = await buildRecord(entry.file, entry.relPath);
      if (result.record) {
        files.push(result.record);
        bytes += result.record.size || 0;
      } else {
        skipped.push({ path: entry.relPath, reason: result.skipped });
      }
      if (done % 20 === 0 || done === entries.length) {
        setProgress(done, entries.length, `Reading ${done} of ${entries.length} files…`);
        await tick();
      }
    }

    return { files, skipped, bytes };
  }

  async function runScan(entries, label, errors) {
    if (state.busy) return;
    if (!entries.length) {
      setStatus('Nothing to scan - that folder had no readable files.', 'error');
      return;
    }
    state.busy = true;
    const results = el('results');
    if (results) results.hidden = true;

    try {
      setStatus('Reading your files…');
      setProgress(0, entries.length, 'Reading 0 of ' + entries.length + ' files…');
      const { files, skipped, bytes } = await ingest(entries);

      if (!files.length) {
        setStatus('None of those files could be read as text, so there was nothing to scan.', 'error');
        hideProgress();
        return;
      }

      setStatus(`Scanning ${files.length} files…`);
      await tick();

      const report = S.scan.scanProject({
        files,
        label: label || 'the selected folder',
        onProgress: ({ done: d, total }) => {
          setProgress(d, total, `Running security checks (${d + 1} of ${total})…`);
        },
      });

      report.skipped = skipped;
      report.readErrors = errors || [];
      state.report = report;
      state.lastLabel = label || 'the selected folder';

      renderReport(report);
      hideProgress();

      const summary = S.lib.report.renderConsoleSummary(report);
      setStatus(
        `Scan complete. ${summary}. ${S.lib.util.plural(files.length, 'file')} read, ` +
          `${S.lib.util.formatBytes(bytes)}.`,
        'done',
      );
      return report;
    } catch (error) {
      hideProgress();
      setStatus(`The scan failed: ${String((error && error.message) || error)}`, 'error');
      return null;
    } finally {
      state.busy = false;
    }
  }

  /* ------------------------------------------------------------------ */
  /* rendering                                                           */
  /* ------------------------------------------------------------------ */

  function copyButton(getText, label) {
    const button = make('button', 'btn btn-ghost btn-sm copy-btn', label || 'Copy');
    button.type = 'button';
    button.addEventListener('click', async () => {
      const text = getText();
      const ok = await copyToClipboard(text);
      button.textContent = ok ? 'Copied' : 'Copy failed';
      button.classList.toggle('copied', ok);
      setTimeout(() => {
        button.textContent = label || 'Copy';
        button.classList.remove('copied');
      }, 1600);
    });
    return button;
  }

  async function copyToClipboard(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      /* fall through to the legacy path */
    }
    try {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(area);
      return ok;
    } catch {
      return false;
    }
  }

  function severityBadge(severity) {
    return make('span', `badge badge-${severity.toLowerCase()}`, severity);
  }

  function renderScoreCard(report) {
    const card = make('div', 'score-card');
    card.dataset.verdict = report.verdict;

    const ring = make('div', 'score-ring');
    ring.setAttribute('role', 'img');
    ring.setAttribute('aria-label', `Ship readiness score ${report.score} out of 100`);
    const value = make('div', 'score-value');
    value.appendChild(make('span', 'score-number', report.score));
    value.appendChild(make('span', 'score-out-of', '/100'));
    ring.appendChild(value);
    card.appendChild(ring);

    const side = make('div', 'score-side');
    side.appendChild(make('h3', 'score-verdict', report.verdict));
    side.appendChild(make('p', 'score-plain', `This means ${report.verdictPlain}`));

    const counts = make('ul', 'count-chips');
    counts.setAttribute('aria-label', 'Findings by severity');
    for (const severity of S.lib.severity.SEVERITIES) {
      if (severity === 'INFO') continue;
      const item = make('li', `count-chip chip-${severity.toLowerCase()}`);
      item.appendChild(make('b', null, report.counts[severity]));
      item.appendChild(make('span', null, severity.charAt(0) + severity.slice(1).toLowerCase()));
      counts.appendChild(item);
    }
    side.appendChild(counts);

    if (report.hasCritical) {
      side.appendChild(
        make(
          'p',
          'critical-note',
          'At least one CRITICAL issue was found, so this project cannot be called ready to ship no matter how ' +
            'high the score is.',
        ),
      );
    }
    card.appendChild(side);
    return card;
  }

  function renderTopFive(report) {
    const section = make('section', 'panel');
    section.appendChild(make('h3', 'panel-title', 'Top 5 things to fix first'));

    const top = S.lib.report.buildTopFive(report);
    if (!top.length) {
      section.appendChild(make('p', 'muted', 'No fixes came back - nothing needed fixing in the files we scanned.'));
      return section;
    }

    const list = make('ol', 'top-list');
    for (const item of top) {
      const entry = make('li', 'top-item');
      const head = make('div', 'top-head');
      head.appendChild(severityBadge(item.severity));
      head.appendChild(make('span', 'top-title', item.title));
      entry.appendChild(head);
      if (item.plain) entry.appendChild(make('p', 'top-plain', item.plain));
      entry.appendChild(make('p', 'top-location', `Where: ${item.location}`));
      entry.appendChild(make('h4', 'mini-title', 'Paste this into your AI assistant (Cursor, Lovable, Bolt, Claude...)'));
      const prompt = make('pre', 'code-block', item.fixPrompt);
      entry.appendChild(prompt);
      const actions = make('div', 'actions');
      actions.appendChild(copyButton(() => item.fixPrompt, 'Copy fix prompt'));
      entry.appendChild(actions);
      list.appendChild(entry);
    }
    section.appendChild(list);
    return section;
  }

  function renderFindings(report) {
    const section = make('section', 'panel');
    section.appendChild(make('h3', 'panel-title', 'All findings'));
    const grouped = S.lib.report.groupBySeverity(report.findings);

    let any = false;
    for (const severity of S.lib.severity.SEVERITIES) {
      const list = grouped[severity] || [];
      if (!list.length) continue;
      any = true;

      const details = make('details', 'severity-group');
      details.open = severity === 'CRITICAL' || severity === 'HIGH';
      const summary = make('summary');
      summary.appendChild(severityBadge(severity));
      summary.appendChild(
        make('span', null, `${severity.charAt(0) + severity.slice(1).toLowerCase()} (${list.length})`),
      );
      details.appendChild(summary);

      for (const finding of list) {
        const item = make('article', 'finding');
        const head = make('div', 'finding-head');
        head.appendChild(severityBadge(finding.severity));
        head.appendChild(make('h4', 'finding-title', finding.title));
        item.appendChild(head);
        item.appendChild(make('p', 'finding-location', `Where: ${finding.location}`));
        if (finding.cwe) item.appendChild(make('p', 'finding-cwe', finding.cwe));
        item.appendChild(make('p', 'finding-detail', finding.detail));

        if (finding.evidence) {
          item.appendChild(make('h5', 'mini-title', 'What we saw (secrets are redacted)'));
          item.appendChild(make('pre', 'code-block', finding.evidence));
        }
        item.appendChild(make('h5', 'mini-title', 'How to fix it'));
        item.appendChild(make('pre', 'code-block', finding.remediation));
        if (finding.fixPrompt) {
          item.appendChild(make('h5', 'mini-title', 'Paste this into your AI assistant'));
          item.appendChild(make('pre', 'code-block', finding.fixPrompt));
          const actions = make('div', 'actions');
          actions.appendChild(copyButton(() => finding.fixPrompt, 'Copy fix prompt'));
          item.appendChild(actions);
        }
        details.appendChild(item);
      }
      section.appendChild(details);
    }

    if (!any) {
      section.appendChild(make('p', 'muted', 'No security issues were found in the files we scanned.'));
    }
    return section;
  }

  function renderNotChecked() {
    const section = make('section', 'panel panel-not-checked');
    section.appendChild(make('h3', 'panel-title', 'What this does NOT check'));
    section.appendChild(
      make(
        'p',
        'muted',
        'This scan ran entirely in your browser, on the files you selected. That makes it fast, private and free - ' +
          'but it also means it stops where your folder stops. Here is exactly what it did not look at.',
      ),
    );
    const list = make('ul', 'not-checked-list');
    for (const item of S.lib.report.NOT_CHECKED) {
      const entry = make('li');
      entry.appendChild(make('b', null, item.title));
      entry.appendChild(make('span', null, ` ${item.detail}`));
      list.appendChild(entry);
    }
    section.appendChild(list);
    return section;
  }

  function renderCheckList(report) {
    const section = make('section', 'panel');
    section.appendChild(make('h3', 'panel-title', 'What was checked'));
    const list = make('ul', 'check-list');
    for (const check of report.checks || []) {
      const entry = make('li', `check check-${check.state}`);
      const label = check.state === 'pass' ? 'Checked, nothing found' : check.state === 'fail' ? 'Found problems' : 'Could not run';
      entry.appendChild(make('span', 'check-state', label));
      entry.appendChild(make('b', null, ` ${check.title}`));
      const notes = (check.notes || []).filter(Boolean);
      for (const note of notes) entry.appendChild(make('span', 'check-note', ` - ${note}`));
      list.appendChild(entry);
    }
    section.appendChild(list);
    return section;
  }

  function renderReport(report) {
    const host = el('results');
    if (!host) return;
    clear(host);

    const head = make('div', 'results-head');
    head.appendChild(renderScoreCard(report));
    host.appendChild(head);

    const summaryPanel = make('section', 'panel');
    summaryPanel.appendChild(make('h3', 'panel-title', 'What this means, in plain English'));
    summaryPanel.appendChild(make('p', 'summary-text', S.lib.report.buildPlainSummary(report)));
    host.appendChild(summaryPanel);

    host.appendChild(renderTopFive(report));

    const toolbar = make('div', 'toolbar');
    const copyAll = copyButton(() => report.markdown, 'Copy the whole report (Markdown)');
    copyAll.classList.add('btn-primary');
    toolbar.appendChild(copyAll);
    const meta = make('span', 'muted small');
    meta.textContent = `${S.lib.util.plural(report.fileCount, 'file')} scanned in ${(
      report.durationMs / 1000
    ).toFixed(1)}s - nothing left your browser.`;
    toolbar.appendChild(meta);
    host.appendChild(toolbar);

    host.appendChild(renderFindings(report));
    host.appendChild(renderCheckList(report));
    host.appendChild(renderNotChecked());

    if (report.skipped && report.skipped.length) {
      const skippedPanel = make('section', 'panel');
      skippedPanel.appendChild(make('h3', 'panel-title', `Files we did not read (${report.skipped.length})`));
      const list = make('ul', 'skipped-list');
      for (const item of report.skipped.slice(0, 200)) {
        list.appendChild(make('li', null, `${item.path} - ${item.reason}`));
      }
      skippedPanel.appendChild(list);
      host.appendChild(skippedPanel);
    }

    if (report.readErrors && report.readErrors.length) {
      const errorPanel = make('section', 'panel panel-error');
      errorPanel.appendChild(make('h3', 'panel-title', 'Things we could not read'));
      const list = make('ul', 'skipped-list');
      for (const message of report.readErrors) list.appendChild(make('li', null, message));
      errorPanel.appendChild(list);
      host.appendChild(errorPanel);
    }

    host.hidden = false;
    host.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  /* ------------------------------------------------------------------ */
  /* wiring                                                              */
  /* ------------------------------------------------------------------ */

  async function handleInput(input) {
    const { entries, label } = await intakeFromInput(input);
    await runScan(entries, label, []);
    input.value = '';
  }

  async function handleDrop(event) {
    event.preventDefault();
    const zone = el('dropzone');
    if (zone) zone.classList.remove('drag-over');
    const { entries, errors, label } = await intakeFromDrop(event.dataTransfer);
    await runScan(entries, label, errors);
  }

  function init() {
    const zone = el('dropzone');
    const folderInput = el('folder-input');
    const filesInput = el('files-input');
    const pickFolder = el('pick-folder');
    const pickFiles = el('pick-files');

    if (pickFolder && folderInput) {
      pickFolder.addEventListener('click', () => folderInput.click());
    }
    if (pickFiles && filesInput) {
      pickFiles.addEventListener('click', () => filesInput.click());
    }
    if (folderInput) {
      folderInput.addEventListener('change', () => handleInput(folderInput));
    }
    if (filesInput) {
      filesInput.addEventListener('change', () => handleInput(filesInput));
    }

    if (zone) {
      zone.addEventListener('dragover', (event) => {
        event.preventDefault();
        event.dataTransfer.dropEffect = 'copy';
        zone.classList.add('drag-over');
      });
      zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
      zone.addEventListener('drop', handleDrop);
      // Clicking the zone opens the folder picker - but not when the click
      // landed on one of the buttons inside it (they have their own handler).
      zone.addEventListener('click', (event) => {
        if (event.target && event.target.closest && event.target.closest('button')) return;
        if (folderInput) folderInput.click();
      });
      // Keyboard reachable: the zone is a button, so Enter and Space work.
      zone.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
          event.preventDefault();
          if (folderInput) folderInput.click();
        }
      });
    }

    // The self-test page is a sibling; make the link work from file:// too.
    const selfTest = el('self-test-link');
    if (selfTest) selfTest.href = 'self-test.html';
  }

  S.app.init = init;
  S.app.runScan = runScan;
  S.app.renderReport = renderReport;
  S.app.intakeFromInput = intakeFromInput;
  S.app.intakeFromDrop = intakeFromDrop;
  S.app.buildRecord = buildRecord;

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }
})(globalThis);
