/**
 * @fileoverview
 * This script provides:
 * 1. Copy-to-clipboard functionality for code blocks.
 * 2. Scroll-triggered animations (fade-in and slide-up) for status and feature cards.
 */

/**
 * Adds click event listeners to all copy buttons to copy code content to the clipboard.
 *
 * @example
 * // HTML structure:
 * // <div class="code-block">
 * //   <pre class="code-content">console.log('Hello World');</pre>
 * //   <button class="code-copy">Copy</button>
 * // </div>
 *
 * // Clicking the copy button copies the code to clipboard and temporarily changes the button text to "Copied!".
 */
document.querySelectorAll(".code-copy").forEach((button) => {
  /**
   * Click event handler for the copy button.
   *
   * @param {MouseEvent} event - The click event object.
   * @returns {void}
   */
  button.addEventListener("click", function (event) {
    /**
     * The closest parent element with class "code-block".
     * @type {HTMLElement|null}
     */
    const codeBlock = this.closest(".code-block");

    if (!codeBlock) return; // Exit if no parent code block found

    /**
     * The code content to copy.
     * @type {string}
     */
    const codeContent =
      codeBlock.querySelector(".code-content")?.textContent || "";

    // Copy the code content to clipboard (async)
    navigator.clipboard
      .writeText(codeContent)
      .then(() => {
        /**
         * Store the original button HTML to restore later.
         * @type {string}
         */
        const originalText = this.innerHTML;

        // Change button content to show success
        this.innerHTML = '<i class="fas fa-check"></i> Copied!';

        // Revert button content after 2 seconds
        setTimeout(() => {
          this.innerHTML = originalText;
        }, 2000);
      })
      .catch((err) => {
        console.error("Failed to copy text: ", err);
      });
  });
});

/**
 * Callback for IntersectionObserver to animate elements when they appear in viewport.
 *
 * @callback IntersectionCallback
 * @param {IntersectionObserverEntry[]} entries - List of observed entries.
 * @param {IntersectionObserver} observer - The IntersectionObserver instance.
 * @returns {void}
 */

/**
 * IntersectionObserver to handle scroll-triggered animations.
 *
 * @type {IntersectionObserver}
 */
const observer = new IntersectionObserver(
  /**
   * @type {IntersectionCallback}
   */
  (entries, observer) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        /** @type {HTMLElement} */
        const element = entry.target;
        element.style.opacity = "1"; // Fade in
        element.style.transform = "translateY(0)"; // Slide up
        observer.unobserve(element); // Stop observing once animated
      }
    });
  },
  {
    threshold: 0.1, // Trigger when 10% of element is visible
  }
);

/**
 * Initialize animation styles and start observing target elements.
 */
document.querySelectorAll(".status-card, .feature-card").forEach((card) => {
  /** @type {HTMLElement} */
  const element = card;
  element.style.opacity = "0"; // Start hidden
  element.style.transform = "translateY(20px)"; // Start below
  element.style.transition = "opacity 0.6s ease, transform 0.6s ease"; // Smooth transition
  observer.observe(element); // Observe visibility changes
});
