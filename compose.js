/* -*- coding: UTF-8, tab-width: 2 -*- */
/*jslint indent: 2, maxlen: 80, continue: true, unparam: true, browser: true */
(function () {
  'use strict';

  function rand36() { return Math.random().toString(36).replace(/^0\./, ''); }

  var setStatus, statusFrame = document.getElementById('submit-status'),
    extractTimeRgx = /^[\s\S]* ([0-9:]{8}) [\s\S]*$/,
    composeForm = document.forms.compose;
  setStatus = function (msg) {
    statusFrame.src = 'data:text/html,' + encodeURIComponent(msg);
  };
  composeForm.onsubmit = function () {
    setStatus('[' + String(new Date()).replace(extractTimeRgx, '$1') +
      '] submitting&hellip;');
    setTimeout(function () { composeForm.submit(); }, 50);
    return false;
  };

  composeForm.elements.genpasswd.onclick = function () {
    var use = window.prompt('random password:', rand36());
    if (use) { composeForm.elements.passwd.value = use; }
  };

  composeForm.elements.sess.value = [rand36(), rand36(), rand36()].join('-');

  setStatus('ready');
}());
