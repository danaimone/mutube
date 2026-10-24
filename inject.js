// Add the TizenTube script and playback options to the page.
(function () {
  if (document.mutube) return;
  document.mutube = true;

  var CFG_KEY = 'ytaf-configuration';
  var origJsonParse = JSON.parse;

  function isSettingEnabled(key) {
    try {
      var raw = window.localStorage.getItem(CFG_KEY);
      return !raw || !new RegExp('"' + key + '"\\s*:\\s*false').test(raw);
    } catch (e) {
      return true;
    }
  }

  try {
    var rawCfg = window.localStorage.getItem(CFG_KEY);
    var parsedCfg = rawCfg ? origJsonParse(rawCfg) : {};
    if (!parsedCfg || typeof parsedCfg !== 'object') parsedCfg = {};
    if (typeof parsedCfg.enableHdr !== 'boolean') {
      parsedCfg.enableHdr = true;
      window.localStorage.setItem(CFG_KEY, JSON.stringify(parsedCfg));
    }
  } catch (e) {}

  var dclFired = false;
  document.addEventListener('DOMContentLoaded', function () { dclFired = true; });
  window.addEventListener('load', function () {
    if (dclFired) return;
    document.dispatchEvent(new Event('DOMContentLoaded'));
    window.dispatchEvent(new Event('DOMContentLoaded'));
  });

  var script = document.createElement('script');
  script.src = "https://cdn.jsdelivr.net/npm/@foxreis/tizentube/dist/userScript.js?v=" + Date.now();
  script.async = true;
  document.head.appendChild(script);

  var HDR_MIME_RE = /vp09\.02|vp9\.2|smpte2084|arib-std-b67|bt2020/i;
  var origIsSupported = window.MediaSource.isTypeSupported.bind(window.MediaSource);

  window.MediaSource.isTypeSupported = function (mimeType) {
    var s = String(mimeType);
    if (!isSettingEnabled('enableHdr') && HDR_MIME_RE.test(s)) return false;
    return origIsSupported(s.replace(/;\s*(width|height)=\d+/gi, ''));
  };

  function isHdrFormat(format) {
    if (!format || typeof format !== 'object') return false;
    return HDR_MIME_RE.test(format.mimeType || '') ||
      /HDR/i.test(format.qualityLabel || '') ||
      (format.colorInfo && /2084|B67|2020/i.test(JSON.stringify(format.colorInfo)));
  }

  JSON.parse = function () {
    var result = origJsonParse.apply(this, arguments);
    try {
      if (result && result.streamingData &&
          Array.isArray(result.streamingData.adaptiveFormats) &&
          !isSettingEnabled('enableHdr')) {
        var formats = result.streamingData.adaptiveFormats;
        var hasSdr = formats.some(function (format) {
          return format && format.mimeType && format.mimeType.indexOf('video/') === 0 && !isHdrFormat(format);
        });
        if (hasSdr) result.streamingData.adaptiveFormats = formats.filter(function (format) {
          return !isHdrFormat(format);
        });
      }
    } catch (e) {}
    return result;
  };

  function createSetting(title, subtitle, icon, key, index) {
    var enabled = isSettingEnabled(key);
    return {
      compactLinkRenderer: {
        title: { simpleText: title },
        subtitle: { simpleText: subtitle },
        icon: { iconType: icon },
        secondaryIcon: { iconType: enabled ? 'CHECK_BOX' : 'CHECK_BOX_OUTLINE_BLANK' },
        serviceEndpoint: {
          commandExecutorCommand: {
            commands: [
              { setClientSettingEndpoint: { settingDatas: [{ clientSettingEnum: { item: key }, boolValue: !enabled }] } },
              { customAction: { action: 'SETTINGS_UPDATE', parameters: [index] } }
            ]
          }
        }
      }
    };
  }

  function patchSettingsPopup(command) {
    if (!command || !command.openPopupAction || command.openPopupAction.uniqueId !== 'tt-settings') return;
    var items = command.openPopupAction.popup.overlaySectionRenderer.overlay.overlayTwoPanelRenderer.actionPanel.overlayPanelRenderer.content.overlayPanelItemListRenderer.items;
    if (!Array.isArray(items) || items.some(function (item) {
      return item && item.compactLinkRenderer && item.compactLinkRenderer.title &&
        item.compactLinkRenderer.title.simpleText === 'Allow HDR';
    })) return;
    items.push(createSetting(
      'Allow HDR',
      'Disable if HDR playback stutters',
      'VIDEO_QUALITY',
      'enableHdr',
      items.length
    ));
  }

  setInterval(function () {
    if (!window._yttv) return;
    for (var key in window._yttv) {
      var instance = window._yttv[key] && window._yttv[key].instance;
      if (instance && typeof instance.resolveCommand === 'function' && !instance.resolveCommand._hdrHooked) {
        let original = instance.resolveCommand;
        instance.resolveCommand = function (command) {
          try { patchSettingsPopup(command); } catch (e) {}
          return original.apply(this, arguments);
        };
        instance.resolveCommand._hdrHooked = true;
      }
    }
  }, 300);

  var QUICK_SKIP_KEY = 'enableQuickSkip';
  var QUICK_SKIP_CONFIG = 'ytaf-configuration';

  function isQuickSkipEnabled() {
    try {
      var config = window.localStorage.getItem(QUICK_SKIP_CONFIG);
      return !config || !new RegExp('"' + QUICK_SKIP_KEY + '"\\s*:\\s*false').test(config);
    } catch (e) {
      return true;
    }
  }

  try {
    var quickSkipConfig = window.localStorage.getItem(QUICK_SKIP_CONFIG);
    var quickSkipSettings = quickSkipConfig ? JSON.parse(quickSkipConfig) : {};
    if (!quickSkipSettings || typeof quickSkipSettings !== 'object') quickSkipSettings = {};
    if (typeof quickSkipSettings[QUICK_SKIP_KEY] !== 'boolean') {
      quickSkipSettings[QUICK_SKIP_KEY] = true;
      window.localStorage.setItem(QUICK_SKIP_CONFIG, JSON.stringify(quickSkipSettings));
    }
  } catch (e) {}


  var pressedQuickSkipKeys = {};

  function isHiddenFromQuickSkip(element) {
    for (; element && element !== document; element = element.parentNode) {
      var style = window.getComputedStyle(element);
      if (element.getAttribute('aria-hidden') === 'true' ||
          (element.classList && element.classList.contains('zylon-hidden')) ||
          style.display === 'none' || style.visibility === 'hidden') return true;
    }
    return false;
  }

  function handleQuickSkipKey(event) {
    if (!isQuickSkipEnabled()) return;
    var key = event.keyCode || event.which;
    if (key !== 37 && key !== 39) return;
    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;

    if (event.type === 'keyup') {
      if (pressedQuickSkipKeys[key]) {
        event.preventDefault();
        event.stopImmediatePropagation();
        delete pressedQuickSkipKeys[key];
      }
      return;
    }

    var video = document.querySelector('video');
    if (!video || video.paused || video.ended) return;

    var target = document.activeElement || event.target;
    if (target && target.closest) {
      var tile = target.closest('ytlr-tile-renderer, ytlr-guide-item, ytlr-pivot-bar-item');
      if (tile && !isHiddenFromQuickSkip(tile)) return;
    }

    var controls = ['ytlr-player-actions-container', 'ytlr-progress-bar'];
    for (var i = 0; i < controls.length; i++) {
      var control = document.querySelector(controls[i]);
      if (control && !isHiddenFromQuickSkip(control)) {
        var style = window.getComputedStyle(control);
        if (style.visibility !== 'hidden' && parseFloat(style.opacity) > 0 &&
            control.getClientRects().length > 0) return;
      }
    }

    pressedQuickSkipKeys[key] = true;
    event.preventDefault();
    event.stopImmediatePropagation();

    var dispatchTarget = event.target && event.target.dispatchEvent ? event.target : document;
    var init = { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true };
    dispatchTarget.dispatchEvent(new KeyboardEvent('keydown', init));
    dispatchTarget.dispatchEvent(new KeyboardEvent('keyup', init));
  }

  document.addEventListener('keydown', handleQuickSkipKey, true);
  document.addEventListener('keyup', handleQuickSkipKey, true);

  function createQuickSkipSetting(index) {
    var enabled = isQuickSkipEnabled();
    return {
      compactLinkRenderer: {
        title: { simpleText: 'Quick Skip' },
        subtitle: { simpleText: 'Skip 10s with Left/Right (Siri Remote Gen 2+)' },
        icon: { iconType: 'FAST_FORWARD' },
        secondaryIcon: { iconType: enabled ? 'CHECK_BOX' : 'CHECK_BOX_OUTLINE_BLANK' },
        serviceEndpoint: {
          commandExecutorCommand: {
            commands: [
              { setClientSettingEndpoint: { settingDatas: [{ clientSettingEnum: { item: QUICK_SKIP_KEY }, boolValue: !enabled }] } },
              { customAction: { action: 'SETTINGS_UPDATE', parameters: [index] } }
            ]
          }
        }
      }
    };
  }

  function addQuickSkipSetting(command) {
    if (!command || !command.openPopupAction || command.openPopupAction.uniqueId !== 'tt-settings') return;
    var items = command.openPopupAction.popup.overlaySectionRenderer.overlay.overlayTwoPanelRenderer.actionPanel.overlayPanelRenderer.content.overlayPanelItemListRenderer.items;
    if (!Array.isArray(items) || items.some(function (item) {
      return item && item.compactLinkRenderer && item.compactLinkRenderer.title &&
        item.compactLinkRenderer.title.simpleText === 'Quick Skip';
    })) return;
    items.push(createQuickSkipSetting(items.length));
  }

  setInterval(function () {
    if (!window._yttv) return;
    for (var key in window._yttv) {
      var instance = window._yttv[key] && window._yttv[key].instance;
      if (instance && typeof instance.resolveCommand === 'function' && !instance.resolveCommand._quickSkipHooked) {
        let original = instance.resolveCommand;
        instance.resolveCommand = function (command) {
          try { addQuickSkipSetting(command); } catch (e) {}
          return original.apply(this, arguments);
        };
        instance.resolveCommand._quickSkipHooked = true;
      }
    }
  }, 300);
})();
