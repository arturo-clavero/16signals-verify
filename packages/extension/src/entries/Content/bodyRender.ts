/**
 * Runs a plugin UI render once <body> exists. The AWS Console content script starts at document_start, so a render
 * can arrive before the body; only the latest pending render runs, as soon as the parser inserts the body.
 */
export function createBodyRenderer(doc: Document = document): (render: () => void) => void {
  let pending: (() => void) | undefined;
  return render => {
    if (doc.body) { pending = undefined; render(); return; }
    const waiting = pending !== undefined;
    pending = render;
    if (waiting) return;
    const observer = new MutationObserver(() => {
      if (!doc.body) return;
      observer.disconnect();
      const run = pending; pending = undefined; run?.();
    });
    observer.observe(doc.documentElement, { childList: true });
  };
}
