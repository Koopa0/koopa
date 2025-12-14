/**
 * Koopa Chat Application JavaScript
 *
 * This file contains event handlers and utilities for the chat interface.
 * All behaviors are attached via event delegation to support dynamically loaded content.
 */

(function () {
  "use strict";

  // ==========================================================================
  // Empty State Handler
  // ==========================================================================

  /**
   * Hide empty state immediately on form submit (before AI response).
   * Uses fade-out animation for smooth transition.
   */
  function handleChatFormBeforeRequest(evt) {
    const form = evt.target;
    if (form.id !== "chat-form") return;

    const emptyState = document.getElementById("empty-state-wrapper");
    if (emptyState) {
      // Smooth fade out using transition classes added to wrapper
      emptyState.classList.add("opacity-0");
      emptyState.addEventListener(
        "transitionend",
        function () {
          emptyState.style.display = "none";
        },
        { once: true },
      );
    }
  }

  // ==========================================================================
  // Chat Form Handlers
  // ==========================================================================

  /**
   * Reset chat form after successful submission.
   * Clears textarea content, resets height, and refocuses.
   */
  function handleChatFormAfterRequest(evt) {
    const form = evt.target;
    if (form.id !== "chat-form") return;

    form.reset();
    const textarea = document.getElementById("chat-input-textarea");
    if (textarea) {
      textarea.focus();
      textarea.style.height = "auto";
    }
  }

  /**
   * Show error toast on HTMX response error.
   * Creates a temporary toast notification that auto-dismisses after 5 seconds.
   */
  function handleResponseError(evt) {
    const form = evt.target;
    if (form.id !== "chat-form") return;

    // Remove existing toast if present
    const existingToast = document.getElementById("chat-error-toast");
    if (existingToast) {
      existingToast.remove();
    }

    // Create new toast
    const toast = document.createElement("div");
    toast.id = "chat-error-toast";
    toast.setAttribute("role", "alert");
    toast.setAttribute("aria-live", "assertive");
    toast.className =
      "fixed bottom-20 left-1/2 -translate-x-1/2 bg-red-500/90 text-white px-4 py-2 rounded-lg shadow-lg z-50 text-sm";
    toast.textContent = "Failed to send. Try again.";
    document.body.appendChild(toast);

    // Auto-dismiss after 5 seconds
    setTimeout(function () {
      toast.remove();
    }, 5000);
  }

  // ==========================================================================
  // Textarea Auto-Resize
  // ==========================================================================

  /**
   * Auto-resize textarea based on content.
   * Maximum height is 200px.
   */
  function handleTextareaInput(evt) {
    const textarea = evt.target;
    if (textarea.id !== "chat-input-textarea") return;

    textarea.style.height = "auto";
    textarea.style.height = Math.min(textarea.scrollHeight, 200) + "px";
  }

  // ==========================================================================
  // Keyboard Shortcuts
  // ==========================================================================

  /**
   * Handle Enter key to submit form.
   * Enter = submit, Shift+Enter = newline.
   */
  function handleTextareaKeydown(evt) {
    const textarea = evt.target;
    if (textarea.id !== "chat-input-textarea") return;

    // Enter without Shift submits the form
    if (evt.key === "Enter" && !evt.shiftKey) {
      evt.preventDefault();

      // Don't submit if textarea is empty
      if (!textarea.value.trim()) return;

      // Find and submit the form - requestSubmit() triggers HTMX properly
      const form = document.getElementById("chat-form");
      if (form) {
        form.requestSubmit();
      }
    }
    // Shift+Enter allows default behavior (newline)
  }

  // ==========================================================================
  // Copy to Clipboard
  // ==========================================================================

  /**
   * Copy message content to clipboard.
   * Shows visual feedback by changing icon color.
   */
  function handleCopyClick(evt) {
    const button = evt.target.closest("[data-copy-content]");
    if (!button) return;

    const content = button.dataset.copyContent;
    if (!content) return;

    navigator.clipboard.writeText(content).then(function () {
      const svg = button.querySelector("svg");
      if (svg) {
        svg.classList.add("text-green-400");
        setTimeout(function () {
          svg.classList.remove("text-green-400");
        }, 1500);
      }
    });
  }

  /**
   * Copy artifact (code block) content to clipboard.
   * Finds the pre element within the artifact container.
   */
  function handleArtifactCopyClick(evt) {
    const button = evt.target.closest("[data-copy-artifact]");
    if (!button) return;

    const artifact = button.closest("[data-artifact]");
    if (!artifact) return;

    const pre = artifact.querySelector("pre");
    if (!pre) return;

    navigator.clipboard.writeText(pre.textContent);
  }

  // ==========================================================================
  // Template Buttons (Empty State)
  // ==========================================================================

  /**
   * Fill textarea with template prompt when template button is clicked.
   */
  function handleTemplateClick(evt) {
    const button = evt.target.closest("[data-prompt]");
    if (!button) return;

    const prompt = button.dataset.prompt;
    if (!prompt) return;

    const textarea = document.getElementById("chat-input-textarea");
    if (textarea) {
      textarea.value = prompt;
      textarea.focus();
    }
  }

  // ==========================================================================
  // Event Listeners
  // ==========================================================================

  // HTMX events (on document)
  document.addEventListener("htmx:beforeRequest", handleChatFormBeforeRequest);
  document.addEventListener("htmx:afterRequest", handleChatFormAfterRequest);
  document.addEventListener("htmx:responseError", handleResponseError);

  // Native events (delegated)
  document.addEventListener("input", handleTextareaInput);
  document.addEventListener("keydown", handleTextareaKeydown);
  document.addEventListener("click", function (evt) {
    handleCopyClick(evt);
    handleArtifactCopyClick(evt);
    handleTemplateClick(evt);
  });
})();
