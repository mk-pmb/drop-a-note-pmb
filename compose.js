/* -*- coding: UTF-8, tab-width: 2 -*- */
/*jslint indent: 2, maxlen: 80, continue: true, unparam: true, browser: true */
(function () {
  'use strict';

  function byid(id) { return document.getElementById(id); }

  function rand36() { return Math.random().toString(36).replace(/^0\./, ''); }

  function sessionId() {
    if (sessionId.cache) { return sessionId.cache; }
    var sessId = /(?:^|;)\s*sess=([A-Za-z0-9_\-]{10,})/.exec(document.cookie);
    if (sessId) {
      sessId = sessId[1];
    } else {
      sessId = [rand36(), rand36(), rand36()].join('-');
      document.cookie = ['sess=' + sessId, 'path=/', 'secure',
        // 'HttpOnly',
        ].join('; ');
    }
    sessionId.cache = sessId;
    return sessId;
  }

  function timeOfDay() {
    var time = String(new Date());
    return ((time.match(/ ([0-9:]{8}) /) || false)[1] || time);
  }

  function setStatus(msg) {
    msg = '[' + timeOfDay() + '] ' + msg;
    byid('submit-status').src = 'data:text/html,' + encodeURIComponent(msg);
  }

  (function initComposeForm() {
    var compoForm = document.forms.compose;
    compoForm.elements.sess.value = sessionId();
    compoForm.onsubmit = function () {
      setStatus('submitting&hellip;');
      setTimeout(function () { compoForm.submit(); }, 50);
      return false;
    };
    compoForm.elements.genpasswd.onclick = function () {
      var use = window.prompt('random password:', rand36());
      if (use) { compoForm.elements.passwd.value = use; }
    };
  }());

  setStatus('ready');
}());
