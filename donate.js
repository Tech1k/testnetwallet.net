// SPDX-License-Identifier: AGPL-3.0-or-later
/* Donation page: copy buttons + locally generated QR codes + theme that matches the wallet.
 * No network requests; everything runs from the vendored qrcode-generator. */
(function(){
  'use strict';
  var LS_KEY = 'testnetwallet.v1';

  /* ---- theme (mirror the wallet, and stay in sync with it) ---- */
  function applyTheme(theme){
    var t = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', t);
    var tt = document.getElementById('theme-toggle');
    if(tt) tt.textContent = t === 'dark' ? '☀' : '☾';   // ☀ in dark / ☾ in light
  }
  function readStore(){ try { return JSON.parse(localStorage.getItem(LS_KEY)) || {}; } catch(_){ return {}; } }
  function saveTheme(t){                                          // round-trip with the wallet's settings, preserving other keys
    try { var s = readStore(); s.settings = s.settings || {}; s.settings.theme = t; localStorage.setItem(LS_KEY, JSON.stringify(s)); } catch(_){}
  }
  var store = readStore();
  applyTheme((store.settings && store.settings.theme) || 'dark');
  var toggle = document.getElementById('theme-toggle');
  if(toggle) toggle.addEventListener('click', function(){
    var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next); saveTheme(next);
  });

  /* ---- QR codes (error-correction H so a centered coin logo is tolerated) ---- */
  function qrEl(text, coin){
    if(!window.qrcode) return null;
    try {
      var qr = qrcode(0, 'H'); qr.addData(text); qr.make();
      var box = document.createElement('div'); box.className = 'qr';
      var img = document.createElement('img'); img.src = qr.createDataURL(6, 8); img.alt = 'QR code'; box.appendChild(img);
      if(coin){
        var logo = document.createElement('div'); logo.className = 'qr-logo';
        var li = document.createElement('img'); li.src = 'icons/' + coin + '.svg'; li.alt = ''; logo.appendChild(li);
        box.appendChild(logo);
      }
      return box;
    } catch(_){ return null; }
  }
  var cards = document.querySelectorAll('[data-coin]');
  for(var i = 0; i < cards.length; i++){
    var card = cards[i];
    var slot = card.querySelector('.qrslot');
    var addr = card.getAttribute('data-addr');
    if(slot && addr){ var q = qrEl(addr, card.getAttribute('data-coin')); if(q) slot.appendChild(q); }
  }

  /* ---- copy buttons ---- */
  function copyText(text, btn){
    var restore = function(){ if(!btn) return; var label = btn.getAttribute('data-label') || btn.textContent;
      btn.setAttribute('data-label', label); btn.textContent = 'Copied!';
      setTimeout(function(){ btn.textContent = btn.getAttribute('data-label'); }, 1200); };
    if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text).then(restore, function(){}); }
    else { try { var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta); restore(); } catch(_){} }
  }
  var btns = document.querySelectorAll('.copybtn');
  for(var j = 0; j < btns.length; j++){
    (function(b){ b.addEventListener('click', function(){ copyText(b.getAttribute('data-copy'), b); }); })(btns[j]);
  }
})();
