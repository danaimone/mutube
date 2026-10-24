// Add the TizenTube script and playback options to the page.
//
// 4K60 cap (test build): stripping width/height hides every size limit from the native capability
// check, and the native HDR patches also lift Google's 4K60 rejection. On devices that decode VP9
// in software and are too slow for 4K60 (Apple TV 4K 1st gen, AppleTV6-2) the video then falls
// behind the audio. Google's own limit for that device is 1440p at any fps, or above 1440p at
// 30fps or less. So unless the device is a known-fast model (2nd gen AppleTV11-1, 3rd gen
// AppleTV14-1), refuse formats above 2560x1440 that are over 30fps or have no framerate given.
// Native patches are left alone, they are fine on the 3rd gen.
//
// HDR cap: HDR is VP9 profile 2 (vp09.02, 10-bit), which is heavier to decode in software than
// SDR. The native vp09.02 hook skips every size/fps check, so on a slow box HDR above 1080p is
// refused when it is over 30fps (measured on a 1st gen: 1080p60 HDR, 1440p30 HDR and 4K30 HDR
// play, 1440p60 HDR stutters and drifts from the audio). BLOCK_4K_HDR also refuses HDR above
// 1440p entirely, for people who see hitches at 4K30 HDR.
//
// Apple TV HD (AppleTV5-3, A8, 1080p max): no hardware VP9, and Google's own native code only
// allows software VP9 up to 1080p at 30fps or less, or 720p at any fps, on boxes that are not
// the 4K 1st gen. We mirror that for VP9 formats. H.264 is left alone (hardware decoded).
//
// SHOW_BANNER prints the cap state and the user agent for 15 seconds after load. Detection is
// confirmed on Apple TV HD (AppleTV5-3), 4K 1st gen (AppleTV6-2) and 4K 3rd gen (AppleTV14-1),
// so by default it only shows on models it does not recognise. Set it to true to force it.
//
(function () {
  if (document.mutube) return;
  document.mutube = true;

  var BLOCK_4K_HDR = false;
  var ua = navigator.userAgent || '';
  var fastBox = /AppleTV(11|14)[-,]1/.test(ua);
  var hdBox = /AppleTV5[-,]3/.test(ua);
  var capOn = !fastBox;
  var SHOW_BANNER = !/AppleTV(5[-,]3|6[-,]2|11[-,]1|14[-,]1)/.test(ua);

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
    if (!dclFired) {
      document.dispatchEvent(new Event('DOMContentLoaded'));
      window.dispatchEvent(new Event('DOMContentLoaded'));
    }
    if (SHOW_BANNER && document.body) {
      var d = document.createElement('div');
      d.style.cssText = 'position:fixed;left:40px;bottom:40px;right:40px;z-index:2147483647;background:#000;color:#fff;font:26px monospace;padding:14px;word-break:break-all;opacity:0.9';
      d.textContent = 'MuTube: ' + (hdBox ? 'CAP ON (Apple TV HD rules)' : (capOn ? 'CAP ON (4K60 blocked)' : 'CAP OFF')) + ' | ' + ua;
      document.body.appendChild(d);
      setTimeout(function () { if (d.parentNode) d.parentNode.removeChild(d); }, 15000);
    }
  });

  var script = document.createElement('script');
  script.src = "https://cdn.jsdelivr.net/npm/@foxreis/tizentube/dist/userScript.js?v=" + Date.now();
  script.async = true;
  document.head.appendChild(script);

  var HDR_MIME_RE = /vp09\.02|vp9\.2|smpte2084|arib-std-b67|bt2020/i;
  var origIsSupported = window.MediaSource.isTypeSupported.bind(window.MediaSource);

  function exceedsDeviceCap(s) {
    var w = 0, h = 0, fps = 0;
    s.split(';').forEach(function (p) {
      var kv = p.trim().split('=');
      if (kv.length === 2) {
        var v = parseFloat(kv[1].replace(/"/g, ''));
        if (kv[0] === 'width') w = v;
        else if (kv[0] === 'height') h = v;
        else if (kv[0] === 'framerate') fps = v;
      }
    });
    if ((w > 2560 || h > 1440) && (!fps || fps > 30)) return true;
    if (hdBox && (s.indexOf('vp09') !== -1 || s.indexOf('vp9') !== -1)) {
      var ok720 = w <= 1280 && h <= 720;
      var ok1080 = w <= 1920 && h <= 1080 && fps > 0 && fps <= 30;
      if (!(ok720 || ok1080)) return true;
    }
    if (s.indexOf('vp09.02') !== -1) {
      if ((w > 1920 || h > 1080) && (!fps || fps > 30)) return true;
      if (BLOCK_4K_HDR && (w > 2560 || h > 1440)) return true;
    }
    return false;
  }

  window.MediaSource.isTypeSupported = function (mimeType) {
    var s = String(mimeType);
    if (!isSettingEnabled('enableHdr') && HDR_MIME_RE.test(s)) return false;
    if (capOn && exceedsDeviceCap(s)) return false;
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

  // One hook for both settings rows. Separate hooks with separate markers each saw the
  // other's wrapper on top and re-wrapped every tick, growing the chain until resolveCommand
  // overflowed the stack and popups (TizenTube's speed menu) stopped opening.
  setInterval(function () {
    if (!window._yttv) return;
    for (var key in window._yttv) {
      var instance = window._yttv[key] && window._yttv[key].instance;
      if (instance && typeof instance.resolveCommand === 'function' && !instance.resolveCommand._mutubeHooked) {
        let original = instance.resolveCommand;
        instance.resolveCommand = function (command) {
          try { patchSettingsPopup(command); } catch (e) {}
          try { addQuickSkipSetting(command); } catch (e) {}
          return original.apply(this, arguments);
        };
        instance.resolveCommand._mutubeHooked = true;
      }
    }
  }, 300);
})();
