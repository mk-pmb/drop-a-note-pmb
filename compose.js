/* -*- coding: UTF-8, tab-width: 2 -*- */
/*jslint indent: 2, maxlen: 80, continue: true, unparam: true, browser: true */
(function () {
  'use strict';

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
  setStatus('ready');

}());
