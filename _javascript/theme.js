/**
 * Theme management class
 *
 * Dark by default (the OS preference is ignored); a visitor's choice made with
 * the topbar toggle is remembered across visits in localStorage.
 *
 * To reduce flickering during page load, this script should be loaded synchronously.
 */
class Theme {
  static #modeKey = 'mode';
  static #modeAttr = 'data-mode';
  static #fallback = 'dark';
  static switchable = !document.documentElement.hasAttribute(this.#modeAttr);

  static get DARK() {
    return 'dark';
  }

  static get LIGHT() {
    return 'light';
  }

  /**
   * @returns {string} Theme mode identifier
   */
  static get ID() {
    return 'theme-mode';
  }

  /**
   * Gets the current visual state of the theme.
   *
   * @returns {string} The applied mode, else the stored one, else the fallback ('dark').
   */
  static get visualState() {
    return (
      document.documentElement.getAttribute(this.#modeAttr) ||
      this.#storedMode ||
      this.#fallback
    );
  }

  static get #storedMode() {
    try {
      const mode = localStorage.getItem(this.#modeKey);
      return mode === this.DARK || mode === this.LIGHT ? mode : null;
    } catch {
      return null; // storage blocked (e.g. strict privacy settings)
    }
  }

  /**
   * Maps theme modes to provided values
   * @param {string} light Value for light mode
   * @param {string} dark Value for dark mode
   * @returns {Object} Mapped values
   */
  static getThemeMapper(light, dark) {
    return {
      [this.LIGHT]: light,
      [this.DARK]: dark
    };
  }

  /**
   * Applies the stored (or fallback) mode before first paint
   */
  static init() {
    if (!this.switchable) {
      return;
    }

    this.#apply(this.#storedMode || this.#fallback);
  }

  /**
   * Flips the current theme mode and remembers the choice
   */
  static flip() {
    const next = this.visualState === this.DARK ? this.LIGHT : this.DARK;

    this.#apply(next);

    try {
      localStorage.setItem(this.#modeKey, next);
    } catch {
      // storage blocked: the switch still applies to the current page
    }

    this.#notify();
  }

  static #apply(mode) {
    document.documentElement.setAttribute(this.#modeAttr, mode);
  }

  /**
   * Notifies other plugins that the theme mode has changed
   */
  static #notify() {
    window.postMessage({ id: this.ID }, '*');
  }
}

Theme.init();

export default Theme;
