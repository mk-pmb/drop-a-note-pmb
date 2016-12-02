/* -*- coding: UTF-8, tab-width: 2 -*- */
/*jslint indent: 2, maxlen: 80, continue: true, unparam: true, browser: true */
(function () {
  'use strict';

  function byid(id) { return document.getElementById(id); }

  function rand36() { return Math.random().toString(36).replace(/^0\./, ''); }
  rand36.sess = [rand36(), rand36(), rand36()].join('-');

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
    compoForm.elements.sess.value = rand36.sess;
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
