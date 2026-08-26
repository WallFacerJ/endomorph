import {
  useEffect,
  useState,
  type ReactNode,
} from "react";

import {
  createPortal,
} from "react-dom";

/**
 * Renders children into a separate browser window.
 *
 * A walkthrough is something you work *alongside* the investigation, not
 * inside it, on a second monitor, or projected while a class follows on
 * their own screens. Rendering through a portal rather than duplicating the
 * component keeps one source of state, so the detached window stays in sync
 * with the run without any message passing.
 *
 * Popups are blocked in plenty of contexts, including sandboxed embeds, so
 * this reports failure rather than silently rendering nothing and the caller
 * falls back to the docked panel.
 */

export interface PopOutWindowProps {
  title: string;
  onClose: () => void;
  onBlocked: () => void;
  children: ReactNode;
}

export function PopOutWindow({
  title,
  onClose,
  onBlocked,
  children,
}: PopOutWindowProps) {
  const [container, setContainer] =
    useState<HTMLElement | null>(null);

  useEffect(() => {
    let popup: Window | null = null;

    try {
      popup = window.open(
        "",
        "endomorph-walkthrough",
        "width=520,height=900,menubar=no,toolbar=no,location=no",
      );
    } catch {
      popup = null;
    }

    if (!popup) {
      onBlocked();
      return;
    }

    popup.document.title = title;

    // The popup is a fresh document with no styles. Copy the host's
    // stylesheets across so the panel looks identical detached.
    for (const node of Array.from(
      document.querySelectorAll(
        'style, link[rel="stylesheet"]',
      ),
    )) {
      popup.document.head.appendChild(
        node.cloneNode(true),
      );
    }

    const theme =
      document.documentElement.dataset
        .theme;

    if (theme) {
      popup.document.documentElement.dataset.theme =
        theme;
    }

    const mount =
      popup.document.createElement("div");

    mount.className =
      "walkthrough-popout-root";

    popup.document.body.appendChild(
      mount,
    );

    setContainer(mount);

    const handleUnload = () => onClose();

    popup.addEventListener(
      "pagehide",
      handleUnload,
    );

    // Closing the host must not orphan the popup.
    const closePopup = () => popup?.close();

    window.addEventListener(
      "pagehide",
      closePopup,
    );

    return () => {
      popup?.removeEventListener(
        "pagehide",
        handleUnload,
      );

      window.removeEventListener(
        "pagehide",
        closePopup,
      );

      popup?.close();
    };
    // Intentionally opens once; title and callbacks are stable per session.
    // eslint-disable-next-line
  }, []);

  if (!container) {
    return null;
  }

  return createPortal(
    children,
    container,
  );
}
