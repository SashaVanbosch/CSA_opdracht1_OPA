// modules are defined as an array
// [ module function, map of requires ]
//
// map of requires is short require name -> numeric require
//
// anything defined in a previous bundle is accessed via the
// orig method which is the require for previous bundles

(function (modules, entry, mainEntry, parcelRequireName, globalName) {
  /* eslint-disable no-undef */
  var globalObject =
    typeof globalThis !== 'undefined'
      ? globalThis
      : typeof self !== 'undefined'
      ? self
      : typeof window !== 'undefined'
      ? window
      : typeof global !== 'undefined'
      ? global
      : {};
  /* eslint-enable no-undef */

  // Save the require from previous bundle to this closure if any
  var previousRequire =
    typeof globalObject[parcelRequireName] === 'function' &&
    globalObject[parcelRequireName];

  var cache = previousRequire.cache || {};
  // Do not use `require` to prevent Webpack from trying to bundle this call
  var nodeRequire =
    typeof module !== 'undefined' &&
    typeof module.require === 'function' &&
    module.require.bind(module);

  function newRequire(name, jumped) {
    if (!cache[name]) {
      if (!modules[name]) {
        // if we cannot find the module within our internal map or
        // cache jump to the current global require ie. the last bundle
        // that was added to the page.
        var currentRequire =
          typeof globalObject[parcelRequireName] === 'function' &&
          globalObject[parcelRequireName];
        if (!jumped && currentRequire) {
          return currentRequire(name, true);
        }

        // If there are other bundles on this page the require from the
        // previous one is saved to 'previousRequire'. Repeat this as
        // many times as there are bundles until the module is found or
        // we exhaust the require chain.
        if (previousRequire) {
          return previousRequire(name, true);
        }

        // Try the node require function if it exists.
        if (nodeRequire && typeof name === 'string') {
          return nodeRequire(name);
        }

        var err = new Error("Cannot find module '" + name + "'");
        err.code = 'MODULE_NOT_FOUND';
        throw err;
      }

      localRequire.resolve = resolve;
      localRequire.cache = {};

      var module = (cache[name] = new newRequire.Module(name));

      modules[name][0].call(
        module.exports,
        localRequire,
        module,
        module.exports,
        this
      );
    }

    return cache[name].exports;

    function localRequire(x) {
      var res = localRequire.resolve(x);
      return res === false ? {} : newRequire(res);
    }

    function resolve(x) {
      var id = modules[name][1][x];
      return id != null ? id : x;
    }
  }

  function Module(moduleName) {
    this.id = moduleName;
    this.bundle = newRequire;
    this.exports = {};
  }

  newRequire.isParcelRequire = true;
  newRequire.Module = Module;
  newRequire.modules = modules;
  newRequire.cache = cache;
  newRequire.parent = previousRequire;
  newRequire.register = function (id, exports) {
    modules[id] = [
      function (require, module) {
        module.exports = exports;
      },
      {},
    ];
  };

  Object.defineProperty(newRequire, 'root', {
    get: function () {
      return globalObject[parcelRequireName];
    },
  });

  globalObject[parcelRequireName] = newRequire;

  for (var i = 0; i < entry.length; i++) {
    newRequire(entry[i]);
  }

  if (mainEntry) {
    // Expose entry point to Node, AMD or browser globals
    // Based on https://github.com/ForbesLindesay/umd/blob/master/template.js
    var mainExports = newRequire(mainEntry);

    // CommonJS
    if (typeof exports === 'object' && typeof module !== 'undefined') {
      module.exports = mainExports;

      // RequireJS
    } else if (typeof define === 'function' && define.amd) {
      define(function () {
        return mainExports;
      });

      // <script>
    } else if (globalName) {
      this[globalName] = mainExports;
    }
  }
})({"3D4o7":[function(require,module,exports) {
var global = arguments[3];
var HMR_HOST = null;
var HMR_PORT = null;
var HMR_SECURE = false;
var HMR_ENV_HASH = "d6ea1d42532a7575";
module.bundle.HMR_BUNDLE_ID = "8e1958085540d938";
"use strict";
/* global HMR_HOST, HMR_PORT, HMR_ENV_HASH, HMR_SECURE, chrome, browser, __parcel__import__, __parcel__importScripts__, ServiceWorkerGlobalScope */ /*::
import type {
  HMRAsset,
  HMRMessage,
} from '@parcel/reporter-dev-server/src/HMRServer.js';
interface ParcelRequire {
  (string): mixed;
  cache: {|[string]: ParcelModule|};
  hotData: {|[string]: mixed|};
  Module: any;
  parent: ?ParcelRequire;
  isParcelRequire: true;
  modules: {|[string]: [Function, {|[string]: string|}]|};
  HMR_BUNDLE_ID: string;
  root: ParcelRequire;
}
interface ParcelModule {
  hot: {|
    data: mixed,
    accept(cb: (Function) => void): void,
    dispose(cb: (mixed) => void): void,
    // accept(deps: Array<string> | string, cb: (Function) => void): void,
    // decline(): void,
    _acceptCallbacks: Array<(Function) => void>,
    _disposeCallbacks: Array<(mixed) => void>,
  |};
}
interface ExtensionContext {
  runtime: {|
    reload(): void,
    getURL(url: string): string;
    getManifest(): {manifest_version: number, ...};
  |};
}
declare var module: {bundle: ParcelRequire, ...};
declare var HMR_HOST: string;
declare var HMR_PORT: string;
declare var HMR_ENV_HASH: string;
declare var HMR_SECURE: boolean;
declare var chrome: ExtensionContext;
declare var browser: ExtensionContext;
declare var __parcel__import__: (string) => Promise<void>;
declare var __parcel__importScripts__: (string) => Promise<void>;
declare var globalThis: typeof self;
declare var ServiceWorkerGlobalScope: Object;
*/ var OVERLAY_ID = "__parcel__error__overlay__";
var OldModule = module.bundle.Module;
function Module(moduleName) {
    OldModule.call(this, moduleName);
    this.hot = {
        data: module.bundle.hotData[moduleName],
        _acceptCallbacks: [],
        _disposeCallbacks: [],
        accept: function(fn) {
            this._acceptCallbacks.push(fn || function() {});
        },
        dispose: function(fn) {
            this._disposeCallbacks.push(fn);
        }
    };
    module.bundle.hotData[moduleName] = undefined;
}
module.bundle.Module = Module;
module.bundle.hotData = {};
var checkedAssets /*: {|[string]: boolean|} */ , assetsToDispose /*: Array<[ParcelRequire, string]> */ , assetsToAccept /*: Array<[ParcelRequire, string]> */ ;
function getHostname() {
    return HMR_HOST || (location.protocol.indexOf("http") === 0 ? location.hostname : "localhost");
}
function getPort() {
    return HMR_PORT || location.port;
}
// eslint-disable-next-line no-redeclare
var parent = module.bundle.parent;
if ((!parent || !parent.isParcelRequire) && typeof WebSocket !== "undefined") {
    var hostname = getHostname();
    var port = getPort();
    var protocol = HMR_SECURE || location.protocol == "https:" && !/localhost|127.0.0.1|0.0.0.0/.test(hostname) ? "wss" : "ws";
    var ws;
    try {
        ws = new WebSocket(protocol + "://" + hostname + (port ? ":" + port : "") + "/");
    } catch (err) {
        if (err.message) console.error(err.message);
        ws = {};
    }
    // Web extension context
    var extCtx = typeof browser === "undefined" ? typeof chrome === "undefined" ? null : chrome : browser;
    // Safari doesn't support sourceURL in error stacks.
    // eval may also be disabled via CSP, so do a quick check.
    var supportsSourceURL = false;
    try {
        (0, eval)('throw new Error("test"); //# sourceURL=test.js');
    } catch (err) {
        supportsSourceURL = err.stack.includes("test.js");
    }
    // $FlowFixMe
    ws.onmessage = async function(event /*: {data: string, ...} */ ) {
        checkedAssets = {} /*: {|[string]: boolean|} */ ;
        assetsToAccept = [];
        assetsToDispose = [];
        var data /*: HMRMessage */  = JSON.parse(event.data);
        if (data.type === "update") {
            // Remove error overlay if there is one
            if (typeof document !== "undefined") removeErrorOverlay();
            let assets = data.assets.filter((asset)=>asset.envHash === HMR_ENV_HASH);
            // Handle HMR Update
            let handled = assets.every((asset)=>{
                return asset.type === "css" || asset.type === "js" && hmrAcceptCheck(module.bundle.root, asset.id, asset.depsByBundle);
            });
            if (handled) {
                console.clear();
                // Dispatch custom event so other runtimes (e.g React Refresh) are aware.
                if (typeof window !== "undefined" && typeof CustomEvent !== "undefined") window.dispatchEvent(new CustomEvent("parcelhmraccept"));
                await hmrApplyUpdates(assets);
                // Dispose all old assets.
                let processedAssets = {} /*: {|[string]: boolean|} */ ;
                for(let i = 0; i < assetsToDispose.length; i++){
                    let id = assetsToDispose[i][1];
                    if (!processedAssets[id]) {
                        hmrDispose(assetsToDispose[i][0], id);
                        processedAssets[id] = true;
                    }
                }
                // Run accept callbacks. This will also re-execute other disposed assets in topological order.
                processedAssets = {};
                for(let i = 0; i < assetsToAccept.length; i++){
                    let id = assetsToAccept[i][1];
                    if (!processedAssets[id]) {
                        hmrAccept(assetsToAccept[i][0], id);
                        processedAssets[id] = true;
                    }
                }
            } else fullReload();
        }
        if (data.type === "error") {
            // Log parcel errors to console
            for (let ansiDiagnostic of data.diagnostics.ansi){
                let stack = ansiDiagnostic.codeframe ? ansiDiagnostic.codeframe : ansiDiagnostic.stack;
                console.error("\uD83D\uDEA8 [parcel]: " + ansiDiagnostic.message + "\n" + stack + "\n\n" + ansiDiagnostic.hints.join("\n"));
            }
            if (typeof document !== "undefined") {
                // Render the fancy html overlay
                removeErrorOverlay();
                var overlay = createErrorOverlay(data.diagnostics.html);
                // $FlowFixMe
                document.body.appendChild(overlay);
            }
        }
    };
    ws.onerror = function(e) {
        if (e.message) console.error(e.message);
    };
    ws.onclose = function() {
        console.warn("[parcel] \uD83D\uDEA8 Connection to the HMR server was lost");
    };
}
function removeErrorOverlay() {
    var overlay = document.getElementById(OVERLAY_ID);
    if (overlay) {
        overlay.remove();
        console.log("[parcel] \u2728 Error resolved");
    }
}
function createErrorOverlay(diagnostics) {
    var overlay = document.createElement("div");
    overlay.id = OVERLAY_ID;
    let errorHTML = '<div style="background: black; opacity: 0.85; font-size: 16px; color: white; position: fixed; height: 100%; width: 100%; top: 0px; left: 0px; padding: 30px; font-family: Menlo, Consolas, monospace; z-index: 9999;">';
    for (let diagnostic of diagnostics){
        let stack = diagnostic.frames.length ? diagnostic.frames.reduce((p, frame)=>{
            return `${p}
<a href="/__parcel_launch_editor?file=${encodeURIComponent(frame.location)}" style="text-decoration: underline; color: #888" onclick="fetch(this.href); return false">${frame.location}</a>
${frame.code}`;
        }, "") : diagnostic.stack;
        errorHTML += `
      <div>
        <div style="font-size: 18px; font-weight: bold; margin-top: 20px;">
          \u{1F6A8} ${diagnostic.message}
        </div>
        <pre>${stack}</pre>
        <div>
          ${diagnostic.hints.map((hint)=>"<div>\uD83D\uDCA1 " + hint + "</div>").join("")}
        </div>
        ${diagnostic.documentation ? `<div>\u{1F4DD} <a style="color: violet" href="${diagnostic.documentation}" target="_blank">Learn more</a></div>` : ""}
      </div>
    `;
    }
    errorHTML += "</div>";
    overlay.innerHTML = errorHTML;
    return overlay;
}
function fullReload() {
    if ("reload" in location) location.reload();
    else if (extCtx && extCtx.runtime && extCtx.runtime.reload) extCtx.runtime.reload();
}
function getParents(bundle, id) /*: Array<[ParcelRequire, string]> */ {
    var modules = bundle.modules;
    if (!modules) return [];
    var parents = [];
    var k, d, dep;
    for(k in modules)for(d in modules[k][1]){
        dep = modules[k][1][d];
        if (dep === id || Array.isArray(dep) && dep[dep.length - 1] === id) parents.push([
            bundle,
            k
        ]);
    }
    if (bundle.parent) parents = parents.concat(getParents(bundle.parent, id));
    return parents;
}
function updateLink(link) {
    var href = link.getAttribute("href");
    if (!href) return;
    var newLink = link.cloneNode();
    newLink.onload = function() {
        if (link.parentNode !== null) // $FlowFixMe
        link.parentNode.removeChild(link);
    };
    newLink.setAttribute("href", // $FlowFixMe
    href.split("?")[0] + "?" + Date.now());
    // $FlowFixMe
    link.parentNode.insertBefore(newLink, link.nextSibling);
}
var cssTimeout = null;
function reloadCSS() {
    if (cssTimeout) return;
    cssTimeout = setTimeout(function() {
        var links = document.querySelectorAll('link[rel="stylesheet"]');
        for(var i = 0; i < links.length; i++){
            // $FlowFixMe[incompatible-type]
            var href /*: string */  = links[i].getAttribute("href");
            var hostname = getHostname();
            var servedFromHMRServer = hostname === "localhost" ? new RegExp("^(https?:\\/\\/(0.0.0.0|127.0.0.1)|localhost):" + getPort()).test(href) : href.indexOf(hostname + ":" + getPort());
            var absolute = /^https?:\/\//i.test(href) && href.indexOf(location.origin) !== 0 && !servedFromHMRServer;
            if (!absolute) updateLink(links[i]);
        }
        cssTimeout = null;
    }, 50);
}
function hmrDownload(asset) {
    if (asset.type === "js") {
        if (typeof document !== "undefined") {
            let script = document.createElement("script");
            script.src = asset.url + "?t=" + Date.now();
            if (asset.outputFormat === "esmodule") script.type = "module";
            return new Promise((resolve, reject)=>{
                var _document$head;
                script.onload = ()=>resolve(script);
                script.onerror = reject;
                (_document$head = document.head) === null || _document$head === void 0 || _document$head.appendChild(script);
            });
        } else if (typeof importScripts === "function") {
            // Worker scripts
            if (asset.outputFormat === "esmodule") return import(asset.url + "?t=" + Date.now());
            else return new Promise((resolve, reject)=>{
                try {
                    importScripts(asset.url + "?t=" + Date.now());
                    resolve();
                } catch (err) {
                    reject(err);
                }
            });
        }
    }
}
async function hmrApplyUpdates(assets) {
    global.parcelHotUpdate = Object.create(null);
    let scriptsToRemove;
    try {
        // If sourceURL comments aren't supported in eval, we need to load
        // the update from the dev server over HTTP so that stack traces
        // are correct in errors/logs. This is much slower than eval, so
        // we only do it if needed (currently just Safari).
        // https://bugs.webkit.org/show_bug.cgi?id=137297
        // This path is also taken if a CSP disallows eval.
        if (!supportsSourceURL) {
            let promises = assets.map((asset)=>{
                var _hmrDownload;
                return (_hmrDownload = hmrDownload(asset)) === null || _hmrDownload === void 0 ? void 0 : _hmrDownload.catch((err)=>{
                    // Web extension fix
                    if (extCtx && extCtx.runtime && extCtx.runtime.getManifest().manifest_version == 3 && typeof ServiceWorkerGlobalScope != "undefined" && global instanceof ServiceWorkerGlobalScope) {
                        extCtx.runtime.reload();
                        return;
                    }
                    throw err;
                });
            });
            scriptsToRemove = await Promise.all(promises);
        }
        assets.forEach(function(asset) {
            hmrApply(module.bundle.root, asset);
        });
    } finally{
        delete global.parcelHotUpdate;
        if (scriptsToRemove) scriptsToRemove.forEach((script)=>{
            if (script) {
                var _document$head2;
                (_document$head2 = document.head) === null || _document$head2 === void 0 || _document$head2.removeChild(script);
            }
        });
    }
}
function hmrApply(bundle /*: ParcelRequire */ , asset /*:  HMRAsset */ ) {
    var modules = bundle.modules;
    if (!modules) return;
    if (asset.type === "css") reloadCSS();
    else if (asset.type === "js") {
        let deps = asset.depsByBundle[bundle.HMR_BUNDLE_ID];
        if (deps) {
            if (modules[asset.id]) {
                // Remove dependencies that are removed and will become orphaned.
                // This is necessary so that if the asset is added back again, the cache is gone, and we prevent a full page reload.
                let oldDeps = modules[asset.id][1];
                for(let dep in oldDeps)if (!deps[dep] || deps[dep] !== oldDeps[dep]) {
                    let id = oldDeps[dep];
                    let parents = getParents(module.bundle.root, id);
                    if (parents.length === 1) hmrDelete(module.bundle.root, id);
                }
            }
            if (supportsSourceURL) // Global eval. We would use `new Function` here but browser
            // support for source maps is better with eval.
            (0, eval)(asset.output);
            // $FlowFixMe
            let fn = global.parcelHotUpdate[asset.id];
            modules[asset.id] = [
                fn,
                deps
            ];
        } else if (bundle.parent) hmrApply(bundle.parent, asset);
    }
}
function hmrDelete(bundle, id) {
    let modules = bundle.modules;
    if (!modules) return;
    if (modules[id]) {
        // Collect dependencies that will become orphaned when this module is deleted.
        let deps = modules[id][1];
        let orphans = [];
        for(let dep in deps){
            let parents = getParents(module.bundle.root, deps[dep]);
            if (parents.length === 1) orphans.push(deps[dep]);
        }
        // Delete the module. This must be done before deleting dependencies in case of circular dependencies.
        delete modules[id];
        delete bundle.cache[id];
        // Now delete the orphans.
        orphans.forEach((id)=>{
            hmrDelete(module.bundle.root, id);
        });
    } else if (bundle.parent) hmrDelete(bundle.parent, id);
}
function hmrAcceptCheck(bundle /*: ParcelRequire */ , id /*: string */ , depsByBundle /*: ?{ [string]: { [string]: string } }*/ ) {
    if (hmrAcceptCheckOne(bundle, id, depsByBundle)) return true;
    // Traverse parents breadth first. All possible ancestries must accept the HMR update, or we'll reload.
    let parents = getParents(module.bundle.root, id);
    let accepted = false;
    while(parents.length > 0){
        let v = parents.shift();
        let a = hmrAcceptCheckOne(v[0], v[1], null);
        if (a) // If this parent accepts, stop traversing upward, but still consider siblings.
        accepted = true;
        else {
            // Otherwise, queue the parents in the next level upward.
            let p = getParents(module.bundle.root, v[1]);
            if (p.length === 0) {
                // If there are no parents, then we've reached an entry without accepting. Reload.
                accepted = false;
                break;
            }
            parents.push(...p);
        }
    }
    return accepted;
}
function hmrAcceptCheckOne(bundle /*: ParcelRequire */ , id /*: string */ , depsByBundle /*: ?{ [string]: { [string]: string } }*/ ) {
    var modules = bundle.modules;
    if (!modules) return;
    if (depsByBundle && !depsByBundle[bundle.HMR_BUNDLE_ID]) {
        // If we reached the root bundle without finding where the asset should go,
        // there's nothing to do. Mark as "accepted" so we don't reload the page.
        if (!bundle.parent) return true;
        return hmrAcceptCheck(bundle.parent, id, depsByBundle);
    }
    if (checkedAssets[id]) return true;
    checkedAssets[id] = true;
    var cached = bundle.cache[id];
    assetsToDispose.push([
        bundle,
        id
    ]);
    if (!cached || cached.hot && cached.hot._acceptCallbacks.length) {
        assetsToAccept.push([
            bundle,
            id
        ]);
        return true;
    }
}
function hmrDispose(bundle /*: ParcelRequire */ , id /*: string */ ) {
    var cached = bundle.cache[id];
    bundle.hotData[id] = {};
    if (cached && cached.hot) cached.hot.data = bundle.hotData[id];
    if (cached && cached.hot && cached.hot._disposeCallbacks.length) cached.hot._disposeCallbacks.forEach(function(cb) {
        cb(bundle.hotData[id]);
    });
    delete bundle.cache[id];
}
function hmrAccept(bundle /*: ParcelRequire */ , id /*: string */ ) {
    // Execute the module.
    bundle(id);
    // Run the accept callbacks in the new version of the module.
    var cached = bundle.cache[id];
    if (cached && cached.hot && cached.hot._acceptCallbacks.length) cached.hot._acceptCallbacks.forEach(function(cb) {
        var assetsToAlsoAccept = cb(function() {
            return getParents(module.bundle.root, id);
        });
        if (assetsToAlsoAccept && assetsToAccept.length) {
            assetsToAlsoAccept.forEach(function(a) {
                hmrDispose(a[0], a[1]);
            });
            // $FlowFixMe[method-unbinding]
            assetsToAccept.push.apply(assetsToAccept, assetsToAlsoAccept);
        }
    });
}

},{}],"kYW5p":[function(require,module,exports) {
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.
var parcelHelpers = require("@parcel/transformer-js/src/esmodule-helpers.js");
parcelHelpers.defineInteropFlag(exports);
parcelHelpers.export(exports, "log", ()=>log);
var _settings = require("./settings");
///////////////////////////////
// UI event handlers
///////////////////////////////
const maxLogEntries = 2; // Set default maximum number of log entries
document.getElementById("clearState").addEventListener("click", clearState, false);
document.getElementById("getUser").addEventListener("click", getUser, false);
document.getElementById("orderFristi").addEventListener("click", orderFristi, false);
document.getElementById("orderBeer").addEventListener("click", orderBeer, false);
document.getElementById("manageDrinks").addEventListener("click", manageDrinks, false);
document.getElementById("clearLogs").addEventListener("click", function() {
    document.getElementById("out").innerHTML = ""; // Clears the content of the log
});
document.getElementById("clearAllLogs").addEventListener("click", function() {
    document.getElementById("out").innerHTML = ""; // Clears the content of the SPA log
    document.getElementById("result").innerText = "";
});
document.getElementById("toggleLogs").addEventListener("click", function() {
    var container = document.querySelector(".block-logs-container");
    if (container.style.display === "none") container.style.display = "";
    else container.style.display = "none";
});
document.getElementById("startSigninMainWindow").addEventListener("click", startSigninMainWindow, false);
document.getElementById("logoutUser").addEventListener("click", startSignoutMainWindow, false);
// Function to extract query parameters
function getQueryParams() {
    const params = {};
    window.location.search.substring(1).split("&").forEach(function(part) {
        const item = part.split("=");
        params[item[0]] = decodeURIComponent(item[1]);
    });
    return params;
}
// Main logic for the index page
document.addEventListener("DOMContentLoaded", ()=>{
    const userManager = new (0, _settings.UserManager)((0, _settings.settings));
    const queryParams = getQueryParams();
    // Check if we were redirected here after a successful login
    if (queryParams.login === "successful") {
        log("Login successful");
        userManager.getUser().then((user)=>{
            if (user) // Perform actions with the user object as needed
            log(`User logged in: ${user.profile.email}`);
            else log("No user logged in");
        }).catch((err)=>{
            log(err);
        });
    }
});
///////////////////////////////
// config
///////////////////////////////
function sendRequest(url, token, data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    // Headers you're setting for the request
    const requestHeaders = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
    };
    // Set headers on the XMLHttpRequest object
    Object.keys(requestHeaders).forEach((key)=>{
        xhr.setRequestHeader(key, requestHeaders[key]);
    });
    // Log the request details including headers
    logRequest(url, data, requestHeaders);
    xhr.onload = function() {
        let response;
        try {
            response = JSON.parse(xhr.responseText);
        } catch (error) {
            response = xhr.responseText;
        }
        // Log the response details
        callback(true, "response", {
            type: "response",
            content: `Response Status: ${xhr.status}\nResponse Data: ${JSON.stringify(response, null, 2)}`
        });
    };
    xhr.send(JSON.stringify(data));
}
function logRequest(url, requestData, requestHeaders) {
    // Format the request log to include headers
    var requestLog = `Request URL: ${url}\nRequest Headers: ${JSON.stringify(requestHeaders, null, 2)}\nRequest Data: ${JSON.stringify(requestData, null, 2)}`;
    log(true, "request", {
        type: "request",
        content: requestLog
    }); // Passing special parameters for HTTP logging
}
function orderFristi() {
    mgr.getUser().then(function(user) {
        console.log(user);
        sendRequest((0, _settings.settings).api_bar_uri, user.access_token, {
            DrinkName: "Fristi"
        }, log);
    });
}
function orderBeer() {
    mgr.getUser().then(function(user) {
        sendRequest((0, _settings.settings).api_bar_uri, user.access_token, {
            DrinkName: "Beer"
        }, log);
    });
}
function manageDrinks() {
    mgr.getUser().then(function(user) {
        sendRequest((0, _settings.settings).api_manageBar_uri, user.access_token, {
            DrinkName: "Whiskey"
        }, log);
    });
}
function log() {
    var logContainer = document.getElementById("out");
    var isSpecialLog = arguments.length > 1 && typeof arguments[0] === "boolean" && typeof arguments[1] === "string";
    var startIndex = isSpecialLog ? 2 : 0;
    var logEntry = document.createElement("div");
    logEntry.className = "http-log";
    Array.prototype.slice.call(arguments, startIndex).forEach(function(msg) {
        var messageElement = document.createElement("div");
        if (typeof msg === "object" && msg !== null && (msg.type === "request" || msg.type === "response")) {
            messageElement.textContent = msg.content + "\r\n";
            messageElement.className = `log-${msg.type}`;
        } else {
            if (msg instanceof Error) msg = "Error: " + msg.message;
            else if (typeof msg !== "string") msg = JSON.stringify(msg, null, 2);
            messageElement.textContent = msg + "\r\n";
        }
        logEntry.appendChild(messageElement);
        if (msg.type === "response") {
            if (msg.content.includes("200")) document.getElementById("result").textContent = "GRANTED";
            else if (msg.content.includes("403")) document.getElementById("result").textContent = "DENIED";
            else document.getElementById("result").textContent = "";
        }
    });
    let separator = document.createElement("div");
    separator.className = "http-transaction-separator";
    logEntry.insertBefore(separator, logEntry.firstChild);
    if (logContainer.children.length >= maxLogEntries) logContainer.removeChild(logContainer.lastChild); // Remove the oldest log entry
    logContainer.insertBefore(logEntry, logContainer.firstChild); // Insert the new log at the top
}
const mgr = new (0, _settings.UserManager)((0, _settings.settings));
///////////////////////////////
// events
///////////////////////////////
mgr.events.addAccessTokenExpiring(function() {
    console.log("token expiring");
    log("token expiring");
});
mgr.events.addAccessTokenExpired(function() {
    console.log("token expired");
    log("token expired");
});
mgr.events.addSilentRenewError(function(e) {
    console.log("silent renew error", e.message);
    log("silent renew error", e.message);
});
mgr.events.addUserLoaded(function(user) {
    console.log("user loaded", user);
    mgr.getUser().then(function() {
        console.log("getUser loaded user after userLoaded event fired");
    }, ()=>{});
});
mgr.events.addUserUnloaded(function(e) {
    console.log("user unloaded");
});
///////////////////////////////
// functions for UI elements
///////////////////////////////
function clearState() {
    mgr.clearStaleState().then(function() {
        log("Stated cleared");
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}
function getUser() {
    mgr.getUser().then(function(user) {
        log("Got user", user);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}
function startSigninMainWindow() {
    mgr.signinRedirect({
        state: {
            some: "data"
        }
    }).then(function() {
        log("Signinredirect done");
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}
function endSigninMainWindow() {
    mgr.signinRedirectCallback().then(function(user) {
        log("Signed in", user);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}
function popupSignin() {
    mgr.signinPopup().then(function(user) {
        log("Signed in", user);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}
function popupSignout() {
    mgr.signoutPopup().then(function() {
        log("signed out");
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}
function iframeSignin() {
    mgr.signinSilent().then(function(user) {
        log("Signed in", user);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}
function startSignoutMainWindow() {
    mgr.signoutRedirect().then(function(resp) {
        log("Signed out", resp);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}
function endSignoutMainWindow() {
    mgr.signoutRedirectCallback().then(function(resp) {
        log("Signed out", resp);
    }).catch(function(err) {
        console.error(err);
        log(err);
    });
}

},{"./settings":"8CP9N","@parcel/transformer-js/src/esmodule-helpers.js":"gkKU3"}],"8CP9N":[function(require,module,exports) {
var parcelHelpers = require("@parcel/transformer-js/src/esmodule-helpers.js");
parcelHelpers.defineInteropFlag(exports);
parcelHelpers.export(exports, "settings", ()=>settings);
parcelHelpers.export(exports, "Log", ()=>(0, _oidcClientTs.Log));
parcelHelpers.export(exports, "UserManager", ()=>(0, _oidcClientTs.UserManager));
var _oidcClientTs = require("oidc-client-ts");
(0, _oidcClientTs.Log).setLogger(console);
(0, _oidcClientTs.Log).setLevel((0, _oidcClientTs.Log).INFO);
const url = window.location.origin + "";
const settings = {
    authority: "https://dev-jugznej8voor6caz.us.auth0.com/",
    client_id: "Hecw8meuIuahCp8vDIVHtQnr1Vf5a6GQ",
    redirect_uri: url + "/callback.html",
    post_logout_redirect_uri: url + "/index.html",
    response_type: "code",
    scope: "openid email roles",
    response_mode: "query",
    filterProtocolClaims: true,
    extraQueryParams: {
        audience: "bar-auth0-api"
    },
    api_bar_uri: "http://localhost:5172/api/bar",
    api_manageBar_uri: "http://localhost:5172/api/managebar"
};

},{"oidc-client-ts":"jXrpQ","@parcel/transformer-js/src/esmodule-helpers.js":"gkKU3"}],"jXrpQ":[function(require,module,exports) {
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all)=>{
    for(var name in all)__defProp(target, name, {
        get: all[name],
        enumerable: true
    });
};
var __copyProps = (to, from, except, desc)=>{
    if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames(from))if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
            get: ()=>from[key],
            enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
        });
    }
    return to;
};
var __toESM = (mod, isNodeMode, target)=>(target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(// If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", {
        value: mod,
        enumerable: true
    }) : target, mod));
var __toCommonJS = (mod)=>__copyProps(__defProp({}, "__esModule", {
        value: true
    }), mod);
// src/index.ts
var src_exports = {};
__export(src_exports, {
    AccessTokenEvents: ()=>AccessTokenEvents,
    CheckSessionIFrame: ()=>CheckSessionIFrame,
    ErrorResponse: ()=>ErrorResponse,
    ErrorTimeout: ()=>ErrorTimeout,
    InMemoryWebStorage: ()=>InMemoryWebStorage,
    Log: ()=>Log,
    Logger: ()=>Logger,
    MetadataService: ()=>MetadataService,
    OidcClient: ()=>OidcClient,
    OidcClientSettingsStore: ()=>OidcClientSettingsStore,
    SessionMonitor: ()=>SessionMonitor,
    SigninResponse: ()=>SigninResponse,
    SigninState: ()=>SigninState,
    SignoutResponse: ()=>SignoutResponse,
    State: ()=>State,
    User: ()=>User,
    UserManager: ()=>UserManager,
    UserManagerSettingsStore: ()=>UserManagerSettingsStore,
    Version: ()=>Version,
    WebStorageStateStore: ()=>WebStorageStateStore
});
module.exports = __toCommonJS(src_exports);
// src/utils/CryptoUtils.ts
var import_core = __toESM(require("cd65f2846f9a9917"));
var import_sha256 = __toESM(require("b081c80cbcca67d0"));
var import_enc_base64 = __toESM(require("69a1441ed613820e"));
var import_enc_utf8 = __toESM(require("46685f198d718556"));
// src/utils/Logger.ts
var nopLogger = {
    debug: ()=>void 0,
    info: ()=>void 0,
    warn: ()=>void 0,
    error: ()=>void 0
};
var level;
var logger;
var Log = /* @__PURE__ */ ((Log2)=>{
    Log2[Log2["NONE"] = 0] = "NONE";
    Log2[Log2["ERROR"] = 1] = "ERROR";
    Log2[Log2["WARN"] = 2] = "WARN";
    Log2[Log2["INFO"] = 3] = "INFO";
    Log2[Log2["DEBUG"] = 4] = "DEBUG";
    return Log2;
})(Log || {});
((Log2)=>{
    function reset() {
        level = 3 /* INFO */ ;
        logger = nopLogger;
    }
    Log2.reset = reset;
    function setLevel(value) {
        if (!(0 /* NONE */  <= value && value <= 4 /* DEBUG */ )) throw new Error("Invalid log level");
        level = value;
    }
    Log2.setLevel = setLevel;
    function setLogger(value) {
        logger = value;
    }
    Log2.setLogger = setLogger;
})(Log || (Log = {}));
var Logger = class {
    constructor(_name){
        this._name = _name;
    }
    /* eslint-disable @typescript-eslint/no-unsafe-enum-comparison */ debug(...args) {
        if (level >= 4 /* DEBUG */ ) logger.debug(Logger._format(this._name, this._method), ...args);
    }
    info(...args) {
        if (level >= 3 /* INFO */ ) logger.info(Logger._format(this._name, this._method), ...args);
    }
    warn(...args) {
        if (level >= 2 /* WARN */ ) logger.warn(Logger._format(this._name, this._method), ...args);
    }
    error(...args) {
        if (level >= 1 /* ERROR */ ) logger.error(Logger._format(this._name, this._method), ...args);
    }
    /* eslint-enable @typescript-eslint/no-unsafe-enum-comparison */ throw(err) {
        this.error(err);
        throw err;
    }
    create(method) {
        const methodLogger = Object.create(this);
        methodLogger._method = method;
        methodLogger.debug("begin");
        return methodLogger;
    }
    static createStatic(name, staticMethod) {
        const staticLogger = new Logger(`${name}.${staticMethod}`);
        staticLogger.debug("begin");
        return staticLogger;
    }
    static _format(name, method) {
        const prefix = `[${name}]`;
        return method ? `${prefix} ${method}:` : prefix;
    }
    /* eslint-disable @typescript-eslint/no-unsafe-enum-comparison */ // helpers for static class methods
    static debug(name, ...args) {
        if (level >= 4 /* DEBUG */ ) logger.debug(Logger._format(name), ...args);
    }
    static info(name, ...args) {
        if (level >= 3 /* INFO */ ) logger.info(Logger._format(name), ...args);
    }
    static warn(name, ...args) {
        if (level >= 2 /* WARN */ ) logger.warn(Logger._format(name), ...args);
    }
    static error(name, ...args) {
        if (level >= 1 /* ERROR */ ) logger.error(Logger._format(name), ...args);
    }
};
Log.reset();
// src/utils/CryptoUtils.ts
var UUID_V4_TEMPLATE = "10000000-1000-4000-8000-100000000000";
var CryptoUtils = class {
    static _randomWord() {
        return import_core.default.lib.WordArray.random(1).words[0];
    }
    /**
   * Generates RFC4122 version 4 guid
   */ static generateUUIDv4() {
        const uuid = UUID_V4_TEMPLATE.replace(/[018]/g, (c)=>(+c ^ CryptoUtils._randomWord() & 15 >> +c / 4).toString(16));
        return uuid.replace(/-/g, "");
    }
    /**
   * PKCE: Generate a code verifier
   */ static generateCodeVerifier() {
        return CryptoUtils.generateUUIDv4() + CryptoUtils.generateUUIDv4() + CryptoUtils.generateUUIDv4();
    }
    /**
   * PKCE: Generate a code challenge
   */ static generateCodeChallenge(code_verifier) {
        try {
            const hashed = (0, import_sha256.default)(code_verifier);
            return import_enc_base64.default.stringify(hashed).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        } catch (err) {
            Logger.error("CryptoUtils.generateCodeChallenge", err);
            throw err;
        }
    }
    /**
   * Generates a base64-encoded string for a basic auth header
   */ static generateBasicAuth(client_id, client_secret) {
        const basicAuth = import_enc_utf8.default.parse([
            client_id,
            client_secret
        ].join(":"));
        return import_enc_base64.default.stringify(basicAuth);
    }
};
// src/utils/Event.ts
var Event = class {
    constructor(_name){
        this._name = _name;
        this._logger = new Logger(`Event('${this._name}')`);
        this._callbacks = [];
    }
    addHandler(cb) {
        this._callbacks.push(cb);
        return ()=>this.removeHandler(cb);
    }
    removeHandler(cb) {
        const idx = this._callbacks.lastIndexOf(cb);
        if (idx >= 0) this._callbacks.splice(idx, 1);
    }
    raise(...ev) {
        this._logger.debug("raise:", ...ev);
        for (const cb of this._callbacks)cb(...ev);
    }
};
// src/utils/JwtUtils.ts
var import_jwt_decode = __toESM(require("3455b80cc963b26"));
var JwtUtils = class {
    // IMPORTANT: doesn't validate the token
    static decode(token) {
        try {
            return (0, import_jwt_decode.default)(token);
        } catch (err) {
            Logger.error("JwtUtils.decode", err);
            throw err;
        }
    }
};
// src/utils/PopupUtils.ts
var PopupUtils = class {
    /**
   * Populates a map of window features with a placement centered in front of
   * the current window. If no explicit width is given, a default value is
   * binned into [800, 720, 600, 480, 360] based on the current window's width.
   */ static center({ ...features }) {
        var _a, _b, _c;
        if (features.width == null) features.width = (_a = [
            800,
            720,
            600,
            480
        ].find((width)=>width <= window.outerWidth / 1.618)) != null ? _a : 360;
        (_b = features.left) != null ? _b : features.left = Math.max(0, Math.round(window.screenX + (window.outerWidth - features.width) / 2));
        if (features.height != null) (_c = features.top) != null ? _c : features.top = Math.max(0, Math.round(window.screenY + (window.outerHeight - features.height) / 2));
        return features;
    }
    static serialize(features) {
        return Object.entries(features).filter(([, value])=>value != null).map(([key, value])=>`${key}=${typeof value !== "boolean" ? value : value ? "yes" : "no"}`).join(",");
    }
};
// src/utils/Timer.ts
var Timer = class extends Event {
    constructor(){
        super(...arguments);
        this._logger = new Logger(`Timer('${this._name}')`);
        this._timerHandle = null;
        this._expiration = 0;
        this._callback = ()=>{
            const diff = this._expiration - Timer.getEpochTime();
            this._logger.debug("timer completes in", diff);
            if (this._expiration <= Timer.getEpochTime()) {
                this.cancel();
                super.raise();
            }
        };
    }
    // get the time
    static getEpochTime() {
        return Math.floor(Date.now() / 1e3);
    }
    init(durationInSeconds) {
        const logger2 = this._logger.create("init");
        durationInSeconds = Math.max(Math.floor(durationInSeconds), 1);
        const expiration = Timer.getEpochTime() + durationInSeconds;
        if (this.expiration === expiration && this._timerHandle) {
            logger2.debug("skipping since already initialized for expiration at", this.expiration);
            return;
        }
        this.cancel();
        logger2.debug("using duration", durationInSeconds);
        this._expiration = expiration;
        const timerDurationInSeconds = Math.min(durationInSeconds, 5);
        this._timerHandle = setInterval(this._callback, timerDurationInSeconds * 1e3);
    }
    get expiration() {
        return this._expiration;
    }
    cancel() {
        this._logger.create("cancel");
        if (this._timerHandle) {
            clearInterval(this._timerHandle);
            this._timerHandle = null;
        }
    }
};
// src/utils/UrlUtils.ts
var UrlUtils = class {
    static readParams(url, responseMode = "query") {
        if (!url) throw new TypeError("Invalid URL");
        const parsedUrl = new URL(url, "http://127.0.0.1");
        const params = parsedUrl[responseMode === "fragment" ? "hash" : "search"];
        return new URLSearchParams(params.slice(1));
    }
};
var URL_STATE_DELIMITER = ";";
// src/errors/ErrorResponse.ts
var ErrorResponse = class extends Error {
    constructor(args, form){
        var _a, _b, _c;
        super(args.error_description || args.error || "");
        this.form = form;
        /** Marker to detect class: "ErrorResponse" */ this.name = "ErrorResponse";
        if (!args.error) {
            Logger.error("ErrorResponse", "No error passed");
            throw new Error("No error passed");
        }
        this.error = args.error;
        this.error_description = (_a = args.error_description) != null ? _a : null;
        this.error_uri = (_b = args.error_uri) != null ? _b : null;
        this.state = args.userState;
        this.session_state = (_c = args.session_state) != null ? _c : null;
        this.url_state = args.url_state;
    }
};
// src/errors/ErrorTimeout.ts
var ErrorTimeout = class extends Error {
    constructor(message){
        super(message);
        /** Marker to detect class: "ErrorTimeout" */ this.name = "ErrorTimeout";
    }
};
// src/AccessTokenEvents.ts
var AccessTokenEvents = class {
    constructor(args){
        this._logger = new Logger("AccessTokenEvents");
        this._expiringTimer = new Timer("Access token expiring");
        this._expiredTimer = new Timer("Access token expired");
        this._expiringNotificationTimeInSeconds = args.expiringNotificationTimeInSeconds;
    }
    load(container) {
        const logger2 = this._logger.create("load");
        if (container.access_token && container.expires_in !== void 0) {
            const duration = container.expires_in;
            logger2.debug("access token present, remaining duration:", duration);
            if (duration > 0) {
                let expiring = duration - this._expiringNotificationTimeInSeconds;
                if (expiring <= 0) expiring = 1;
                logger2.debug("registering expiring timer, raising in", expiring, "seconds");
                this._expiringTimer.init(expiring);
            } else {
                logger2.debug("canceling existing expiring timer because we're past expiration.");
                this._expiringTimer.cancel();
            }
            const expired = duration + 1;
            logger2.debug("registering expired timer, raising in", expired, "seconds");
            this._expiredTimer.init(expired);
        } else {
            this._expiringTimer.cancel();
            this._expiredTimer.cancel();
        }
    }
    unload() {
        this._logger.debug("unload: canceling existing access token timers");
        this._expiringTimer.cancel();
        this._expiredTimer.cancel();
    }
    /**
   * Add callback: Raised prior to the access token expiring.
   */ addAccessTokenExpiring(cb) {
        return this._expiringTimer.addHandler(cb);
    }
    /**
   * Remove callback: Raised prior to the access token expiring.
   */ removeAccessTokenExpiring(cb) {
        this._expiringTimer.removeHandler(cb);
    }
    /**
   * Add callback: Raised after the access token has expired.
   */ addAccessTokenExpired(cb) {
        return this._expiredTimer.addHandler(cb);
    }
    /**
   * Remove callback: Raised after the access token has expired.
   */ removeAccessTokenExpired(cb) {
        this._expiredTimer.removeHandler(cb);
    }
};
// src/CheckSessionIFrame.ts
var CheckSessionIFrame = class {
    constructor(_callback, _client_id, url, _intervalInSeconds, _stopOnError){
        this._callback = _callback;
        this._client_id = _client_id;
        this._intervalInSeconds = _intervalInSeconds;
        this._stopOnError = _stopOnError;
        this._logger = new Logger("CheckSessionIFrame");
        this._timer = null;
        this._session_state = null;
        this._message = (e)=>{
            if (e.origin === this._frame_origin && e.source === this._frame.contentWindow) {
                if (e.data === "error") {
                    this._logger.error("error message from check session op iframe");
                    if (this._stopOnError) this.stop();
                } else if (e.data === "changed") {
                    this._logger.debug("changed message from check session op iframe");
                    this.stop();
                    this._callback();
                } else this._logger.debug(e.data + " message from check session op iframe");
            }
        };
        const parsedUrl = new URL(url);
        this._frame_origin = parsedUrl.origin;
        this._frame = window.document.createElement("iframe");
        this._frame.style.visibility = "hidden";
        this._frame.style.position = "fixed";
        this._frame.style.left = "-1000px";
        this._frame.style.top = "0";
        this._frame.width = "0";
        this._frame.height = "0";
        this._frame.src = parsedUrl.href;
    }
    load() {
        return new Promise((resolve)=>{
            this._frame.onload = ()=>{
                resolve();
            };
            window.document.body.appendChild(this._frame);
            window.addEventListener("message", this._message, false);
        });
    }
    start(session_state) {
        if (this._session_state === session_state) return;
        this._logger.create("start");
        this.stop();
        this._session_state = session_state;
        const send = ()=>{
            if (!this._frame.contentWindow || !this._session_state) return;
            this._frame.contentWindow.postMessage(this._client_id + " " + this._session_state, this._frame_origin);
        };
        send();
        this._timer = setInterval(send, this._intervalInSeconds * 1e3);
    }
    stop() {
        this._logger.create("stop");
        this._session_state = null;
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
    }
};
// src/InMemoryWebStorage.ts
var InMemoryWebStorage = class {
    constructor(){
        this._logger = new Logger("InMemoryWebStorage");
        this._data = {};
    }
    clear() {
        this._logger.create("clear");
        this._data = {};
    }
    getItem(key) {
        this._logger.create(`getItem('${key}')`);
        return this._data[key];
    }
    setItem(key, value) {
        this._logger.create(`setItem('${key}')`);
        this._data[key] = value;
    }
    removeItem(key) {
        this._logger.create(`removeItem('${key}')`);
        delete this._data[key];
    }
    get length() {
        return Object.getOwnPropertyNames(this._data).length;
    }
    key(index) {
        return Object.getOwnPropertyNames(this._data)[index];
    }
};
// src/JsonService.ts
var JsonService = class {
    constructor(additionalContentTypes = [], _jwtHandler = null, _extraHeaders = {}){
        this._jwtHandler = _jwtHandler;
        this._extraHeaders = _extraHeaders;
        this._logger = new Logger("JsonService");
        this._contentTypes = [];
        this._contentTypes.push(...additionalContentTypes, "application/json");
        if (_jwtHandler) this._contentTypes.push("application/jwt");
    }
    async fetchWithTimeout(input, init = {}) {
        const { timeoutInSeconds, ...initFetch } = init;
        if (!timeoutInSeconds) return await fetch(input, initFetch);
        const controller = new AbortController();
        const timeoutId = setTimeout(()=>controller.abort(), timeoutInSeconds * 1e3);
        try {
            const response = await fetch(input, {
                ...init,
                signal: controller.signal
            });
            return response;
        } catch (err) {
            if (err instanceof DOMException && err.name === "AbortError") throw new ErrorTimeout("Network timed out");
            throw err;
        } finally{
            clearTimeout(timeoutId);
        }
    }
    async getJson(url, { token, credentials } = {}) {
        const logger2 = this._logger.create("getJson");
        const headers = {
            "Accept": this._contentTypes.join(", ")
        };
        if (token) {
            logger2.debug("token passed, setting Authorization header");
            headers["Authorization"] = "Bearer " + token;
        }
        this.appendExtraHeaders(headers);
        let response;
        try {
            logger2.debug("url:", url);
            response = await this.fetchWithTimeout(url, {
                method: "GET",
                headers,
                credentials
            });
        } catch (err) {
            logger2.error("Network Error");
            throw err;
        }
        logger2.debug("HTTP response received, status", response.status);
        const contentType = response.headers.get("Content-Type");
        if (contentType && !this._contentTypes.find((item)=>contentType.startsWith(item))) logger2.throw(new Error(`Invalid response Content-Type: ${contentType != null ? contentType : "undefined"}, from URL: ${url}`));
        if (response.ok && this._jwtHandler && (contentType == null ? void 0 : contentType.startsWith("application/jwt"))) return await this._jwtHandler(await response.text());
        let json;
        try {
            json = await response.json();
        } catch (err) {
            logger2.error("Error parsing JSON response", err);
            if (response.ok) throw err;
            throw new Error(`${response.statusText} (${response.status})`);
        }
        if (!response.ok) {
            logger2.error("Error from server:", json);
            if (json.error) throw new ErrorResponse(json);
            throw new Error(`${response.statusText} (${response.status}): ${JSON.stringify(json)}`);
        }
        return json;
    }
    async postForm(url, { body, basicAuth, timeoutInSeconds, initCredentials }) {
        const logger2 = this._logger.create("postForm");
        const headers = {
            "Accept": this._contentTypes.join(", "),
            "Content-Type": "application/x-www-form-urlencoded"
        };
        if (basicAuth !== void 0) headers["Authorization"] = "Basic " + basicAuth;
        this.appendExtraHeaders(headers);
        let response;
        try {
            logger2.debug("url:", url);
            response = await this.fetchWithTimeout(url, {
                method: "POST",
                headers,
                body,
                timeoutInSeconds,
                credentials: initCredentials
            });
        } catch (err) {
            logger2.error("Network error");
            throw err;
        }
        logger2.debug("HTTP response received, status", response.status);
        const contentType = response.headers.get("Content-Type");
        if (contentType && !this._contentTypes.find((item)=>contentType.startsWith(item))) throw new Error(`Invalid response Content-Type: ${contentType != null ? contentType : "undefined"}, from URL: ${url}`);
        const responseText = await response.text();
        let json = {};
        if (responseText) try {
            json = JSON.parse(responseText);
        } catch (err) {
            logger2.error("Error parsing JSON response", err);
            if (response.ok) throw err;
            throw new Error(`${response.statusText} (${response.status})`);
        }
        if (!response.ok) {
            logger2.error("Error from server:", json);
            if (json.error) throw new ErrorResponse(json, body);
            throw new Error(`${response.statusText} (${response.status}): ${JSON.stringify(json)}`);
        }
        return json;
    }
    appendExtraHeaders(headers) {
        const logger2 = this._logger.create("appendExtraHeaders");
        const customKeys = Object.keys(this._extraHeaders);
        const protectedHeaders = [
            "authorization",
            "accept",
            "content-type"
        ];
        if (customKeys.length === 0) return;
        customKeys.forEach((headerName)=>{
            if (protectedHeaders.includes(headerName.toLocaleLowerCase())) {
                logger2.warn("Protected header could not be overridden", headerName, protectedHeaders);
                return;
            }
            const content = typeof this._extraHeaders[headerName] === "function" ? this._extraHeaders[headerName]() : this._extraHeaders[headerName];
            if (content && content !== "") headers[headerName] = content;
        });
    }
};
// src/MetadataService.ts
var MetadataService = class {
    constructor(_settings){
        this._settings = _settings;
        this._logger = new Logger("MetadataService");
        this._signingKeys = null;
        this._metadata = null;
        this._metadataUrl = this._settings.metadataUrl;
        this._jsonService = new JsonService([
            "application/jwk-set+json"
        ], null, this._settings.extraHeaders);
        if (this._settings.signingKeys) {
            this._logger.debug("using signingKeys from settings");
            this._signingKeys = this._settings.signingKeys;
        }
        if (this._settings.metadata) {
            this._logger.debug("using metadata from settings");
            this._metadata = this._settings.metadata;
        }
        if (this._settings.fetchRequestCredentials) {
            this._logger.debug("using fetchRequestCredentials from settings");
            this._fetchRequestCredentials = this._settings.fetchRequestCredentials;
        }
    }
    resetSigningKeys() {
        this._signingKeys = null;
    }
    async getMetadata() {
        const logger2 = this._logger.create("getMetadata");
        if (this._metadata) {
            logger2.debug("using cached values");
            return this._metadata;
        }
        if (!this._metadataUrl) {
            logger2.throw(new Error("No authority or metadataUrl configured on settings"));
            throw null;
        }
        logger2.debug("getting metadata from", this._metadataUrl);
        const metadata = await this._jsonService.getJson(this._metadataUrl, {
            credentials: this._fetchRequestCredentials
        });
        logger2.debug("merging remote JSON with seed metadata");
        this._metadata = Object.assign({}, this._settings.metadataSeed, metadata);
        return this._metadata;
    }
    getIssuer() {
        return this._getMetadataProperty("issuer");
    }
    getAuthorizationEndpoint() {
        return this._getMetadataProperty("authorization_endpoint");
    }
    getUserInfoEndpoint() {
        return this._getMetadataProperty("userinfo_endpoint");
    }
    getTokenEndpoint(optional = true) {
        return this._getMetadataProperty("token_endpoint", optional);
    }
    getCheckSessionIframe() {
        return this._getMetadataProperty("check_session_iframe", true);
    }
    getEndSessionEndpoint() {
        return this._getMetadataProperty("end_session_endpoint", true);
    }
    getRevocationEndpoint(optional = true) {
        return this._getMetadataProperty("revocation_endpoint", optional);
    }
    getKeysEndpoint(optional = true) {
        return this._getMetadataProperty("jwks_uri", optional);
    }
    async _getMetadataProperty(name, optional = false) {
        const logger2 = this._logger.create(`_getMetadataProperty('${name}')`);
        const metadata = await this.getMetadata();
        logger2.debug("resolved");
        if (metadata[name] === void 0) {
            if (optional === true) {
                logger2.warn("Metadata does not contain optional property");
                return void 0;
            }
            logger2.throw(new Error("Metadata does not contain property " + name));
        }
        return metadata[name];
    }
    async getSigningKeys() {
        const logger2 = this._logger.create("getSigningKeys");
        if (this._signingKeys) {
            logger2.debug("returning signingKeys from cache");
            return this._signingKeys;
        }
        const jwks_uri = await this.getKeysEndpoint(false);
        logger2.debug("got jwks_uri", jwks_uri);
        const keySet = await this._jsonService.getJson(jwks_uri);
        logger2.debug("got key set", keySet);
        if (!Array.isArray(keySet.keys)) {
            logger2.throw(new Error("Missing keys on keyset"));
            throw null;
        }
        this._signingKeys = keySet.keys;
        return this._signingKeys;
    }
};
// src/WebStorageStateStore.ts
var WebStorageStateStore = class {
    constructor({ prefix = "oidc.", store = localStorage } = {}){
        this._logger = new Logger("WebStorageStateStore");
        this._store = store;
        this._prefix = prefix;
    }
    async set(key, value) {
        this._logger.create(`set('${key}')`);
        key = this._prefix + key;
        await this._store.setItem(key, value);
    }
    async get(key) {
        this._logger.create(`get('${key}')`);
        key = this._prefix + key;
        const item = await this._store.getItem(key);
        return item;
    }
    async remove(key) {
        this._logger.create(`remove('${key}')`);
        key = this._prefix + key;
        const item = await this._store.getItem(key);
        await this._store.removeItem(key);
        return item;
    }
    async getAllKeys() {
        this._logger.create("getAllKeys");
        const len = await this._store.length;
        const keys = [];
        for(let index = 0; index < len; index++){
            const key = await this._store.key(index);
            if (key && key.indexOf(this._prefix) === 0) keys.push(key.substr(this._prefix.length));
        }
        return keys;
    }
};
// src/OidcClientSettings.ts
var DefaultResponseType = "code";
var DefaultScope = "openid";
var DefaultClientAuthentication = "client_secret_post";
var DefaultResponseMode = "query";
var DefaultStaleStateAgeInSeconds = 900;
var DefaultClockSkewInSeconds = 300;
var OidcClientSettingsStore = class {
    constructor({ // metadata related
    authority, metadataUrl, metadata, signingKeys, metadataSeed, // client related
    client_id, client_secret, response_type = DefaultResponseType, scope = DefaultScope, redirect_uri, post_logout_redirect_uri, client_authentication = DefaultClientAuthentication, // optional protocol
    prompt, display, max_age, ui_locales, acr_values, resource, response_mode = DefaultResponseMode, // behavior flags
    filterProtocolClaims = true, loadUserInfo = false, staleStateAgeInSeconds = DefaultStaleStateAgeInSeconds, clockSkewInSeconds = DefaultClockSkewInSeconds, userInfoJwtIssuer = "OP", mergeClaims = false, disablePKCE = false, // other behavior
    stateStore, refreshTokenCredentials, revokeTokenAdditionalContentTypes, fetchRequestCredentials, refreshTokenAllowedScope, // extra
    extraQueryParams = {}, extraTokenParams = {}, extraHeaders = {} }){
        this.authority = authority;
        if (metadataUrl) this.metadataUrl = metadataUrl;
        else {
            this.metadataUrl = authority;
            if (authority) {
                if (!this.metadataUrl.endsWith("/")) this.metadataUrl += "/";
                this.metadataUrl += ".well-known/openid-configuration";
            }
        }
        this.metadata = metadata;
        this.metadataSeed = metadataSeed;
        this.signingKeys = signingKeys;
        this.client_id = client_id;
        this.client_secret = client_secret;
        this.response_type = response_type;
        this.scope = scope;
        this.redirect_uri = redirect_uri;
        this.post_logout_redirect_uri = post_logout_redirect_uri;
        this.client_authentication = client_authentication;
        this.prompt = prompt;
        this.display = display;
        this.max_age = max_age;
        this.ui_locales = ui_locales;
        this.acr_values = acr_values;
        this.resource = resource;
        this.response_mode = response_mode;
        this.filterProtocolClaims = filterProtocolClaims != null ? filterProtocolClaims : true;
        this.loadUserInfo = !!loadUserInfo;
        this.staleStateAgeInSeconds = staleStateAgeInSeconds;
        this.clockSkewInSeconds = clockSkewInSeconds;
        this.userInfoJwtIssuer = userInfoJwtIssuer;
        this.mergeClaims = !!mergeClaims;
        this.disablePKCE = !!disablePKCE;
        this.revokeTokenAdditionalContentTypes = revokeTokenAdditionalContentTypes;
        if (fetchRequestCredentials && refreshTokenCredentials) console.warn("Both fetchRequestCredentials and refreshTokenCredentials is set. Only fetchRequestCredentials will be used.");
        this.fetchRequestCredentials = fetchRequestCredentials ? fetchRequestCredentials : refreshTokenCredentials ? refreshTokenCredentials : "same-origin";
        if (stateStore) this.stateStore = stateStore;
        else {
            const store = typeof window !== "undefined" ? window.localStorage : new InMemoryWebStorage();
            this.stateStore = new WebStorageStateStore({
                store
            });
        }
        this.refreshTokenAllowedScope = refreshTokenAllowedScope;
        this.extraQueryParams = extraQueryParams;
        this.extraTokenParams = extraTokenParams;
        this.extraHeaders = extraHeaders;
    }
};
// src/UserInfoService.ts
var UserInfoService = class {
    constructor(_settings, _metadataService){
        this._settings = _settings;
        this._metadataService = _metadataService;
        this._logger = new Logger("UserInfoService");
        this._getClaimsFromJwt = async (responseText)=>{
            const logger2 = this._logger.create("_getClaimsFromJwt");
            try {
                const payload = JwtUtils.decode(responseText);
                logger2.debug("JWT decoding successful");
                return payload;
            } catch (err) {
                logger2.error("Error parsing JWT response");
                throw err;
            }
        };
        this._jsonService = new JsonService(void 0, this._getClaimsFromJwt, this._settings.extraHeaders);
    }
    async getClaims(token) {
        const logger2 = this._logger.create("getClaims");
        if (!token) this._logger.throw(new Error("No token passed"));
        const url = await this._metadataService.getUserInfoEndpoint();
        logger2.debug("got userinfo url", url);
        const claims = await this._jsonService.getJson(url, {
            token,
            credentials: this._settings.fetchRequestCredentials
        });
        logger2.debug("got claims", claims);
        return claims;
    }
};
// src/TokenClient.ts
var TokenClient = class {
    constructor(_settings, _metadataService){
        this._settings = _settings;
        this._metadataService = _metadataService;
        this._logger = new Logger("TokenClient");
        this._jsonService = new JsonService(this._settings.revokeTokenAdditionalContentTypes, null, this._settings.extraHeaders);
    }
    /**
   * Exchange code.
   *
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
   */ async exchangeCode({ grant_type = "authorization_code", redirect_uri = this._settings.redirect_uri, client_id = this._settings.client_id, client_secret = this._settings.client_secret, ...args }) {
        const logger2 = this._logger.create("exchangeCode");
        if (!client_id) logger2.throw(new Error("A client_id is required"));
        if (!redirect_uri) logger2.throw(new Error("A redirect_uri is required"));
        if (!args.code) logger2.throw(new Error("A code is required"));
        const params = new URLSearchParams({
            grant_type,
            redirect_uri
        });
        for (const [key, value] of Object.entries(args))if (value != null) params.set(key, value);
        let basicAuth;
        switch(this._settings.client_authentication){
            case "client_secret_basic":
                if (!client_secret) {
                    logger2.throw(new Error("A client_secret is required"));
                    throw null;
                }
                basicAuth = CryptoUtils.generateBasicAuth(client_id, client_secret);
                break;
            case "client_secret_post":
                params.append("client_id", client_id);
                if (client_secret) params.append("client_secret", client_secret);
                break;
        }
        const url = await this._metadataService.getTokenEndpoint(false);
        logger2.debug("got token endpoint");
        const response = await this._jsonService.postForm(url, {
            body: params,
            basicAuth,
            initCredentials: this._settings.fetchRequestCredentials
        });
        logger2.debug("got response");
        return response;
    }
    /**
   * Exchange credentials.
   *
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.3.2
   */ async exchangeCredentials({ grant_type = "password", client_id = this._settings.client_id, client_secret = this._settings.client_secret, scope = this._settings.scope, ...args }) {
        const logger2 = this._logger.create("exchangeCredentials");
        if (!client_id) logger2.throw(new Error("A client_id is required"));
        const params = new URLSearchParams({
            grant_type,
            scope
        });
        for (const [key, value] of Object.entries(args))if (value != null) params.set(key, value);
        let basicAuth;
        switch(this._settings.client_authentication){
            case "client_secret_basic":
                if (!client_secret) {
                    logger2.throw(new Error("A client_secret is required"));
                    throw null;
                }
                basicAuth = CryptoUtils.generateBasicAuth(client_id, client_secret);
                break;
            case "client_secret_post":
                params.append("client_id", client_id);
                if (client_secret) params.append("client_secret", client_secret);
                break;
        }
        const url = await this._metadataService.getTokenEndpoint(false);
        logger2.debug("got token endpoint");
        const response = await this._jsonService.postForm(url, {
            body: params,
            basicAuth,
            initCredentials: this._settings.fetchRequestCredentials
        });
        logger2.debug("got response");
        return response;
    }
    /**
   * Exchange a refresh token.
   *
   * @see https://www.rfc-editor.org/rfc/rfc6749#section-6
   */ async exchangeRefreshToken({ grant_type = "refresh_token", client_id = this._settings.client_id, client_secret = this._settings.client_secret, timeoutInSeconds, ...args }) {
        const logger2 = this._logger.create("exchangeRefreshToken");
        if (!client_id) logger2.throw(new Error("A client_id is required"));
        if (!args.refresh_token) logger2.throw(new Error("A refresh_token is required"));
        const params = new URLSearchParams({
            grant_type
        });
        for (const [key, value] of Object.entries(args)){
            if (Array.isArray(value)) value.forEach((param)=>params.append(key, param));
            else if (value != null) params.set(key, value);
        }
        let basicAuth;
        switch(this._settings.client_authentication){
            case "client_secret_basic":
                if (!client_secret) {
                    logger2.throw(new Error("A client_secret is required"));
                    throw null;
                }
                basicAuth = CryptoUtils.generateBasicAuth(client_id, client_secret);
                break;
            case "client_secret_post":
                params.append("client_id", client_id);
                if (client_secret) params.append("client_secret", client_secret);
                break;
        }
        const url = await this._metadataService.getTokenEndpoint(false);
        logger2.debug("got token endpoint");
        const response = await this._jsonService.postForm(url, {
            body: params,
            basicAuth,
            timeoutInSeconds,
            initCredentials: this._settings.fetchRequestCredentials
        });
        logger2.debug("got response");
        return response;
    }
    /**
   * Revoke an access or refresh token.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
   */ async revoke(args) {
        var _a;
        const logger2 = this._logger.create("revoke");
        if (!args.token) logger2.throw(new Error("A token is required"));
        const url = await this._metadataService.getRevocationEndpoint(false);
        logger2.debug(`got revocation endpoint, revoking ${(_a = args.token_type_hint) != null ? _a : "default token type"}`);
        const params = new URLSearchParams();
        for (const [key, value] of Object.entries(args))if (value != null) params.set(key, value);
        params.set("client_id", this._settings.client_id);
        if (this._settings.client_secret) params.set("client_secret", this._settings.client_secret);
        await this._jsonService.postForm(url, {
            body: params
        });
        logger2.debug("got response");
    }
};
// src/ResponseValidator.ts
var ResponseValidator = class {
    constructor(_settings, _metadataService, _claimsService){
        this._settings = _settings;
        this._metadataService = _metadataService;
        this._claimsService = _claimsService;
        this._logger = new Logger("ResponseValidator");
        this._userInfoService = new UserInfoService(this._settings, this._metadataService);
        this._tokenClient = new TokenClient(this._settings, this._metadataService);
    }
    async validateSigninResponse(response, state) {
        const logger2 = this._logger.create("validateSigninResponse");
        this._processSigninState(response, state);
        logger2.debug("state processed");
        await this._processCode(response, state);
        logger2.debug("code processed");
        if (response.isOpenId) this._validateIdTokenAttributes(response);
        logger2.debug("tokens validated");
        await this._processClaims(response, state == null ? void 0 : state.skipUserInfo, response.isOpenId);
        logger2.debug("claims processed");
    }
    async validateCredentialsResponse(response, skipUserInfo) {
        const logger2 = this._logger.create("validateCredentialsResponse");
        if (response.isOpenId && !!response.id_token) this._validateIdTokenAttributes(response);
        logger2.debug("tokens validated");
        await this._processClaims(response, skipUserInfo, response.isOpenId);
        logger2.debug("claims processed");
    }
    async validateRefreshResponse(response, state) {
        var _a, _b;
        const logger2 = this._logger.create("validateRefreshResponse");
        response.userState = state.data;
        (_a = response.session_state) != null ? _a : response.session_state = state.session_state;
        (_b = response.scope) != null ? _b : response.scope = state.scope;
        if (response.isOpenId && !!response.id_token) {
            this._validateIdTokenAttributes(response, state.id_token);
            logger2.debug("ID Token validated");
        }
        if (!response.id_token) {
            response.id_token = state.id_token;
            response.profile = state.profile;
        }
        const hasIdToken = response.isOpenId && !!response.id_token;
        await this._processClaims(response, false, hasIdToken);
        logger2.debug("claims processed");
    }
    validateSignoutResponse(response, state) {
        const logger2 = this._logger.create("validateSignoutResponse");
        if (state.id !== response.state) logger2.throw(new Error("State does not match"));
        logger2.debug("state validated");
        response.userState = state.data;
        if (response.error) {
            logger2.warn("Response was error", response.error);
            throw new ErrorResponse(response);
        }
    }
    _processSigninState(response, state) {
        var _a;
        const logger2 = this._logger.create("_processSigninState");
        if (state.id !== response.state) logger2.throw(new Error("State does not match"));
        if (!state.client_id) logger2.throw(new Error("No client_id on state"));
        if (!state.authority) logger2.throw(new Error("No authority on state"));
        if (this._settings.authority !== state.authority) logger2.throw(new Error("authority mismatch on settings vs. signin state"));
        if (this._settings.client_id && this._settings.client_id !== state.client_id) logger2.throw(new Error("client_id mismatch on settings vs. signin state"));
        logger2.debug("state validated");
        response.userState = state.data;
        response.url_state = state.url_state;
        (_a = response.scope) != null ? _a : response.scope = state.scope;
        if (response.error) {
            logger2.warn("Response was error", response.error);
            throw new ErrorResponse(response);
        }
        if (state.code_verifier && !response.code) logger2.throw(new Error("Expected code in response"));
    }
    async _processClaims(response, skipUserInfo = false, validateSub = true) {
        const logger2 = this._logger.create("_processClaims");
        response.profile = this._claimsService.filterProtocolClaims(response.profile);
        if (skipUserInfo || !this._settings.loadUserInfo || !response.access_token) {
            logger2.debug("not loading user info");
            return;
        }
        logger2.debug("loading user info");
        const claims = await this._userInfoService.getClaims(response.access_token);
        logger2.debug("user info claims received from user info endpoint");
        if (validateSub && claims.sub !== response.profile.sub) logger2.throw(new Error("subject from UserInfo response does not match subject in ID Token"));
        response.profile = this._claimsService.mergeClaims(response.profile, this._claimsService.filterProtocolClaims(claims));
        logger2.debug("user info claims received, updated profile:", response.profile);
    }
    async _processCode(response, state) {
        const logger2 = this._logger.create("_processCode");
        if (response.code) {
            logger2.debug("Validating code");
            const tokenResponse = await this._tokenClient.exchangeCode({
                client_id: state.client_id,
                client_secret: state.client_secret,
                code: response.code,
                redirect_uri: state.redirect_uri,
                code_verifier: state.code_verifier,
                ...state.extraTokenParams
            });
            Object.assign(response, tokenResponse);
        } else logger2.debug("No code to process");
    }
    _validateIdTokenAttributes(response, existingToken) {
        var _a;
        const logger2 = this._logger.create("_validateIdTokenAttributes");
        logger2.debug("decoding ID Token JWT");
        const incoming = JwtUtils.decode((_a = response.id_token) != null ? _a : "");
        if (!incoming.sub) logger2.throw(new Error("ID Token is missing a subject claim"));
        if (existingToken) {
            const existing = JwtUtils.decode(existingToken);
            if (incoming.sub !== existing.sub) logger2.throw(new Error("sub in id_token does not match current sub"));
            if (incoming.auth_time && incoming.auth_time !== existing.auth_time) logger2.throw(new Error("auth_time in id_token does not match original auth_time"));
            if (incoming.azp && incoming.azp !== existing.azp) logger2.throw(new Error("azp in id_token does not match original azp"));
            if (!incoming.azp && existing.azp) logger2.throw(new Error("azp not in id_token, but present in original id_token"));
        }
        response.profile = incoming;
    }
};
// src/State.ts
var State = class {
    constructor(args){
        this.id = args.id || CryptoUtils.generateUUIDv4();
        this.data = args.data;
        if (args.created && args.created > 0) this.created = args.created;
        else this.created = Timer.getEpochTime();
        this.request_type = args.request_type;
        this.url_state = args.url_state;
    }
    toStorageString() {
        new Logger("State").create("toStorageString");
        return JSON.stringify({
            id: this.id,
            data: this.data,
            created: this.created,
            request_type: this.request_type,
            url_state: this.url_state
        });
    }
    static fromStorageString(storageString) {
        Logger.createStatic("State", "fromStorageString");
        return new State(JSON.parse(storageString));
    }
    static async clearStaleState(storage, age) {
        const logger2 = Logger.createStatic("State", "clearStaleState");
        const cutoff = Timer.getEpochTime() - age;
        const keys = await storage.getAllKeys();
        logger2.debug("got keys", keys);
        for(let i = 0; i < keys.length; i++){
            const key = keys[i];
            const item = await storage.get(key);
            let remove = false;
            if (item) try {
                const state = State.fromStorageString(item);
                logger2.debug("got item from key:", key, state.created);
                if (state.created <= cutoff) remove = true;
            } catch (err) {
                logger2.error("Error parsing state for key:", key, err);
                remove = true;
            }
            else {
                logger2.debug("no item in storage for key:", key);
                remove = true;
            }
            if (remove) {
                logger2.debug("removed item for key:", key);
                storage.remove(key);
            }
        }
    }
};
// src/SigninState.ts
var SigninState = class extends State {
    constructor(args){
        super(args);
        if (args.code_verifier === true) this.code_verifier = CryptoUtils.generateCodeVerifier();
        else if (args.code_verifier) this.code_verifier = args.code_verifier;
        if (this.code_verifier) this.code_challenge = CryptoUtils.generateCodeChallenge(this.code_verifier);
        this.authority = args.authority;
        this.client_id = args.client_id;
        this.redirect_uri = args.redirect_uri;
        this.scope = args.scope;
        this.client_secret = args.client_secret;
        this.extraTokenParams = args.extraTokenParams;
        this.response_mode = args.response_mode;
        this.skipUserInfo = args.skipUserInfo;
    }
    toStorageString() {
        new Logger("SigninState").create("toStorageString");
        return JSON.stringify({
            id: this.id,
            data: this.data,
            created: this.created,
            request_type: this.request_type,
            url_state: this.url_state,
            code_verifier: this.code_verifier,
            authority: this.authority,
            client_id: this.client_id,
            redirect_uri: this.redirect_uri,
            scope: this.scope,
            client_secret: this.client_secret,
            extraTokenParams: this.extraTokenParams,
            response_mode: this.response_mode,
            skipUserInfo: this.skipUserInfo
        });
    }
    static fromStorageString(storageString) {
        Logger.createStatic("SigninState", "fromStorageString");
        const data = JSON.parse(storageString);
        return new SigninState(data);
    }
};
// src/SigninRequest.ts
var SigninRequest = class {
    constructor({ // mandatory
    url, authority, client_id, redirect_uri, response_type, scope, // optional
    state_data, response_mode, request_type, client_secret, nonce, url_state, resource, skipUserInfo, extraQueryParams, extraTokenParams, disablePKCE, ...optionalParams }){
        this._logger = new Logger("SigninRequest");
        if (!url) {
            this._logger.error("ctor: No url passed");
            throw new Error("url");
        }
        if (!client_id) {
            this._logger.error("ctor: No client_id passed");
            throw new Error("client_id");
        }
        if (!redirect_uri) {
            this._logger.error("ctor: No redirect_uri passed");
            throw new Error("redirect_uri");
        }
        if (!response_type) {
            this._logger.error("ctor: No response_type passed");
            throw new Error("response_type");
        }
        if (!scope) {
            this._logger.error("ctor: No scope passed");
            throw new Error("scope");
        }
        if (!authority) {
            this._logger.error("ctor: No authority passed");
            throw new Error("authority");
        }
        this.state = new SigninState({
            data: state_data,
            request_type,
            url_state,
            code_verifier: !disablePKCE,
            client_id,
            authority,
            redirect_uri,
            response_mode,
            client_secret,
            scope,
            extraTokenParams,
            skipUserInfo
        });
        const parsedUrl = new URL(url);
        parsedUrl.searchParams.append("client_id", client_id);
        parsedUrl.searchParams.append("redirect_uri", redirect_uri);
        parsedUrl.searchParams.append("response_type", response_type);
        parsedUrl.searchParams.append("scope", scope);
        if (nonce) parsedUrl.searchParams.append("nonce", nonce);
        let state = this.state.id;
        if (url_state) state = `${state}${URL_STATE_DELIMITER}${url_state}`;
        parsedUrl.searchParams.append("state", state);
        if (this.state.code_challenge) {
            parsedUrl.searchParams.append("code_challenge", this.state.code_challenge);
            parsedUrl.searchParams.append("code_challenge_method", "S256");
        }
        if (resource) {
            const resources = Array.isArray(resource) ? resource : [
                resource
            ];
            resources.forEach((r)=>parsedUrl.searchParams.append("resource", r));
        }
        for (const [key, value] of Object.entries({
            response_mode,
            ...optionalParams,
            ...extraQueryParams
        }))if (value != null) parsedUrl.searchParams.append(key, value.toString());
        this.url = parsedUrl.href;
    }
};
// src/SigninResponse.ts
var OidcScope = "openid";
var SigninResponse = class {
    constructor(params){
        /** @see {@link User.access_token} */ this.access_token = "";
        /** @see {@link User.token_type} */ this.token_type = "";
        /** @see {@link User.profile} */ this.profile = {};
        this.state = params.get("state");
        this.session_state = params.get("session_state");
        if (this.state) {
            const splitState = decodeURIComponent(this.state).split(URL_STATE_DELIMITER);
            this.state = splitState[0];
            if (splitState.length > 1) this.url_state = splitState.slice(1).join(URL_STATE_DELIMITER);
        }
        this.error = params.get("error");
        this.error_description = params.get("error_description");
        this.error_uri = params.get("error_uri");
        this.code = params.get("code");
    }
    get expires_in() {
        if (this.expires_at === void 0) return void 0;
        return this.expires_at - Timer.getEpochTime();
    }
    set expires_in(value) {
        if (typeof value === "string") value = Number(value);
        if (value !== void 0 && value >= 0) this.expires_at = Math.floor(value) + Timer.getEpochTime();
    }
    get isOpenId() {
        var _a;
        return ((_a = this.scope) == null ? void 0 : _a.split(" ").includes(OidcScope)) || !!this.id_token;
    }
};
// src/SignoutRequest.ts
var SignoutRequest = class {
    constructor({ url, state_data, id_token_hint, post_logout_redirect_uri, extraQueryParams, request_type, client_id }){
        this._logger = new Logger("SignoutRequest");
        if (!url) {
            this._logger.error("ctor: No url passed");
            throw new Error("url");
        }
        const parsedUrl = new URL(url);
        if (id_token_hint) parsedUrl.searchParams.append("id_token_hint", id_token_hint);
        if (client_id) parsedUrl.searchParams.append("client_id", client_id);
        if (post_logout_redirect_uri) {
            parsedUrl.searchParams.append("post_logout_redirect_uri", post_logout_redirect_uri);
            if (state_data) {
                this.state = new State({
                    data: state_data,
                    request_type
                });
                parsedUrl.searchParams.append("state", this.state.id);
            }
        }
        for (const [key, value] of Object.entries({
            ...extraQueryParams
        }))if (value != null) parsedUrl.searchParams.append(key, value.toString());
        this.url = parsedUrl.href;
    }
};
// src/SignoutResponse.ts
var SignoutResponse = class {
    constructor(params){
        this.state = params.get("state");
        this.error = params.get("error");
        this.error_description = params.get("error_description");
        this.error_uri = params.get("error_uri");
    }
};
// src/ClaimsService.ts
var DefaultProtocolClaims = [
    "nbf",
    "jti",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "azp",
    "at_hash"
];
var InternalRequiredProtocolClaims = [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat"
];
var ClaimsService = class {
    constructor(_settings){
        this._settings = _settings;
        this._logger = new Logger("ClaimsService");
    }
    filterProtocolClaims(claims) {
        const result = {
            ...claims
        };
        if (this._settings.filterProtocolClaims) {
            let protocolClaims;
            if (Array.isArray(this._settings.filterProtocolClaims)) protocolClaims = this._settings.filterProtocolClaims;
            else protocolClaims = DefaultProtocolClaims;
            for (const claim of protocolClaims)if (!InternalRequiredProtocolClaims.includes(claim)) delete result[claim];
        }
        return result;
    }
    mergeClaims(claims1, claims2) {
        const result = {
            ...claims1
        };
        for (const [claim, values] of Object.entries(claims2))for (const value of Array.isArray(values) ? values : [
            values
        ]){
            const previousValue = result[claim];
            if (previousValue === void 0) result[claim] = value;
            else if (Array.isArray(previousValue)) {
                if (!previousValue.includes(value)) previousValue.push(value);
            } else if (result[claim] !== value) {
                if (typeof value === "object" && this._settings.mergeClaims) result[claim] = this.mergeClaims(previousValue, value);
                else result[claim] = [
                    previousValue,
                    value
                ];
            }
        }
        return result;
    }
};
// src/OidcClient.ts
var OidcClient = class {
    constructor(settings, metadataService){
        this._logger = new Logger("OidcClient");
        this.settings = settings instanceof OidcClientSettingsStore ? settings : new OidcClientSettingsStore(settings);
        this.metadataService = metadataService != null ? metadataService : new MetadataService(this.settings);
        this._claimsService = new ClaimsService(this.settings);
        this._validator = new ResponseValidator(this.settings, this.metadataService, this._claimsService);
        this._tokenClient = new TokenClient(this.settings, this.metadataService);
    }
    async createSigninRequest({ state, request, request_uri, request_type, id_token_hint, login_hint, skipUserInfo, nonce, url_state, response_type = this.settings.response_type, scope = this.settings.scope, redirect_uri = this.settings.redirect_uri, prompt = this.settings.prompt, display = this.settings.display, max_age = this.settings.max_age, ui_locales = this.settings.ui_locales, acr_values = this.settings.acr_values, resource = this.settings.resource, response_mode = this.settings.response_mode, extraQueryParams = this.settings.extraQueryParams, extraTokenParams = this.settings.extraTokenParams }) {
        const logger2 = this._logger.create("createSigninRequest");
        if (response_type !== "code") throw new Error("Only the Authorization Code flow (with PKCE) is supported");
        const url = await this.metadataService.getAuthorizationEndpoint();
        logger2.debug("Received authorization endpoint", url);
        const signinRequest = new SigninRequest({
            url,
            authority: this.settings.authority,
            client_id: this.settings.client_id,
            redirect_uri,
            response_type,
            scope,
            state_data: state,
            url_state,
            prompt,
            display,
            max_age,
            ui_locales,
            id_token_hint,
            login_hint,
            acr_values,
            resource,
            request,
            request_uri,
            extraQueryParams,
            extraTokenParams,
            request_type,
            response_mode,
            client_secret: this.settings.client_secret,
            skipUserInfo,
            nonce,
            disablePKCE: this.settings.disablePKCE
        });
        await this.clearStaleState();
        const signinState = signinRequest.state;
        await this.settings.stateStore.set(signinState.id, signinState.toStorageString());
        return signinRequest;
    }
    async readSigninResponseState(url, removeState = false) {
        const logger2 = this._logger.create("readSigninResponseState");
        const response = new SigninResponse(UrlUtils.readParams(url, this.settings.response_mode));
        if (!response.state) {
            logger2.throw(new Error("No state in response"));
            throw null;
        }
        const storedStateString = await this.settings.stateStore[removeState ? "remove" : "get"](response.state);
        if (!storedStateString) {
            logger2.throw(new Error("No matching state found in storage"));
            throw null;
        }
        const state = SigninState.fromStorageString(storedStateString);
        return {
            state,
            response
        };
    }
    async processSigninResponse(url) {
        const logger2 = this._logger.create("processSigninResponse");
        const { state, response } = await this.readSigninResponseState(url, true);
        logger2.debug("received state from storage; validating response");
        await this._validator.validateSigninResponse(response, state);
        return response;
    }
    async processResourceOwnerPasswordCredentials({ username, password, skipUserInfo = false, extraTokenParams = {} }) {
        const tokenResponse = await this._tokenClient.exchangeCredentials({
            username,
            password,
            ...extraTokenParams
        });
        const signinResponse = new SigninResponse(new URLSearchParams());
        Object.assign(signinResponse, tokenResponse);
        await this._validator.validateCredentialsResponse(signinResponse, skipUserInfo);
        return signinResponse;
    }
    async useRefreshToken({ state, timeoutInSeconds }) {
        var _a;
        const logger2 = this._logger.create("useRefreshToken");
        let scope;
        if (this.settings.refreshTokenAllowedScope === void 0) scope = state.scope;
        else {
            const allowableScopes = this.settings.refreshTokenAllowedScope.split(" ");
            const providedScopes = ((_a = state.scope) == null ? void 0 : _a.split(" ")) || [];
            scope = providedScopes.filter((s)=>allowableScopes.includes(s)).join(" ");
        }
        const result = await this._tokenClient.exchangeRefreshToken({
            refresh_token: state.refresh_token,
            resource: state.resource,
            // provide the (possible filtered) scope list
            scope,
            timeoutInSeconds
        });
        const response = new SigninResponse(new URLSearchParams());
        Object.assign(response, result);
        logger2.debug("validating response", response);
        await this._validator.validateRefreshResponse(response, {
            ...state,
            // overide the scope in the state handed over to the validator
            // so it can set the granted scope to the requested scope in case none is included in the response
            scope
        });
        return response;
    }
    async createSignoutRequest({ state, id_token_hint, client_id, request_type, post_logout_redirect_uri = this.settings.post_logout_redirect_uri, extraQueryParams = this.settings.extraQueryParams } = {}) {
        const logger2 = this._logger.create("createSignoutRequest");
        const url = await this.metadataService.getEndSessionEndpoint();
        if (!url) {
            logger2.throw(new Error("No end session endpoint"));
            throw null;
        }
        logger2.debug("Received end session endpoint", url);
        if (!client_id && post_logout_redirect_uri && !id_token_hint) client_id = this.settings.client_id;
        const request = new SignoutRequest({
            url,
            id_token_hint,
            client_id,
            post_logout_redirect_uri,
            state_data: state,
            extraQueryParams,
            request_type
        });
        await this.clearStaleState();
        const signoutState = request.state;
        if (signoutState) {
            logger2.debug("Signout request has state to persist");
            await this.settings.stateStore.set(signoutState.id, signoutState.toStorageString());
        }
        return request;
    }
    async readSignoutResponseState(url, removeState = false) {
        const logger2 = this._logger.create("readSignoutResponseState");
        const response = new SignoutResponse(UrlUtils.readParams(url, this.settings.response_mode));
        if (!response.state) {
            logger2.debug("No state in response");
            if (response.error) {
                logger2.warn("Response was error:", response.error);
                throw new ErrorResponse(response);
            }
            return {
                state: void 0,
                response
            };
        }
        const storedStateString = await this.settings.stateStore[removeState ? "remove" : "get"](response.state);
        if (!storedStateString) {
            logger2.throw(new Error("No matching state found in storage"));
            throw null;
        }
        const state = State.fromStorageString(storedStateString);
        return {
            state,
            response
        };
    }
    async processSignoutResponse(url) {
        const logger2 = this._logger.create("processSignoutResponse");
        const { state, response } = await this.readSignoutResponseState(url, true);
        if (state) {
            logger2.debug("Received state from storage; validating response");
            this._validator.validateSignoutResponse(response, state);
        } else logger2.debug("No state from storage; skipping response validation");
        return response;
    }
    clearStaleState() {
        this._logger.create("clearStaleState");
        return State.clearStaleState(this.settings.stateStore, this.settings.staleStateAgeInSeconds);
    }
    async revokeToken(token, type) {
        this._logger.create("revokeToken");
        return await this._tokenClient.revoke({
            token,
            token_type_hint: type
        });
    }
};
// src/SessionMonitor.ts
var SessionMonitor = class {
    constructor(_userManager){
        this._userManager = _userManager;
        this._logger = new Logger("SessionMonitor");
        this._start = async (user)=>{
            const session_state = user.session_state;
            if (!session_state) return;
            const logger2 = this._logger.create("_start");
            if (user.profile) {
                this._sub = user.profile.sub;
                this._sid = user.profile.sid;
                logger2.debug("session_state", session_state, ", sub", this._sub);
            } else {
                this._sub = void 0;
                this._sid = void 0;
                logger2.debug("session_state", session_state, ", anonymous user");
            }
            if (this._checkSessionIFrame) {
                this._checkSessionIFrame.start(session_state);
                return;
            }
            try {
                const url = await this._userManager.metadataService.getCheckSessionIframe();
                if (url) {
                    logger2.debug("initializing check session iframe");
                    const client_id = this._userManager.settings.client_id;
                    const intervalInSeconds = this._userManager.settings.checkSessionIntervalInSeconds;
                    const stopOnError = this._userManager.settings.stopCheckSessionOnError;
                    const checkSessionIFrame = new CheckSessionIFrame(this._callback, client_id, url, intervalInSeconds, stopOnError);
                    await checkSessionIFrame.load();
                    this._checkSessionIFrame = checkSessionIFrame;
                    checkSessionIFrame.start(session_state);
                } else logger2.warn("no check session iframe found in the metadata");
            } catch (err) {
                logger2.error("Error from getCheckSessionIframe:", err instanceof Error ? err.message : err);
            }
        };
        this._stop = ()=>{
            const logger2 = this._logger.create("_stop");
            this._sub = void 0;
            this._sid = void 0;
            if (this._checkSessionIFrame) this._checkSessionIFrame.stop();
            if (this._userManager.settings.monitorAnonymousSession) {
                const timerHandle = setInterval(async ()=>{
                    clearInterval(timerHandle);
                    try {
                        const session = await this._userManager.querySessionStatus();
                        if (session) {
                            const tmpUser = {
                                session_state: session.session_state,
                                profile: session.sub && session.sid ? {
                                    sub: session.sub,
                                    sid: session.sid
                                } : null
                            };
                            this._start(tmpUser);
                        }
                    } catch (err) {
                        logger2.error("error from querySessionStatus", err instanceof Error ? err.message : err);
                    }
                }, 1e3);
            }
        };
        this._callback = async ()=>{
            const logger2 = this._logger.create("_callback");
            try {
                const session = await this._userManager.querySessionStatus();
                let raiseEvent = true;
                if (session && this._checkSessionIFrame) {
                    if (session.sub === this._sub) {
                        raiseEvent = false;
                        this._checkSessionIFrame.start(session.session_state);
                        if (session.sid === this._sid) logger2.debug("same sub still logged in at OP, restarting check session iframe; session_state", session.session_state);
                        else {
                            logger2.debug("same sub still logged in at OP, session state has changed, restarting check session iframe; session_state", session.session_state);
                            this._userManager.events._raiseUserSessionChanged();
                        }
                    } else logger2.debug("different subject signed into OP", session.sub);
                } else logger2.debug("subject no longer signed into OP");
                if (raiseEvent) {
                    if (this._sub) this._userManager.events._raiseUserSignedOut();
                    else this._userManager.events._raiseUserSignedIn();
                } else logger2.debug("no change in session detected, no event to raise");
            } catch (err) {
                if (this._sub) {
                    logger2.debug("Error calling queryCurrentSigninSession; raising signed out event", err);
                    this._userManager.events._raiseUserSignedOut();
                }
            }
        };
        if (!_userManager) this._logger.throw(new Error("No user manager passed"));
        this._userManager.events.addUserLoaded(this._start);
        this._userManager.events.addUserUnloaded(this._stop);
        this._init().catch((err)=>{
            this._logger.error(err);
        });
    }
    async _init() {
        this._logger.create("_init");
        const user = await this._userManager.getUser();
        if (user) this._start(user);
        else if (this._userManager.settings.monitorAnonymousSession) {
            const session = await this._userManager.querySessionStatus();
            if (session) {
                const tmpUser = {
                    session_state: session.session_state,
                    profile: session.sub && session.sid ? {
                        sub: session.sub,
                        sid: session.sid
                    } : null
                };
                this._start(tmpUser);
            }
        }
    }
};
// src/User.ts
var User = class {
    constructor(args){
        var _a;
        this.id_token = args.id_token;
        this.session_state = (_a = args.session_state) != null ? _a : null;
        this.access_token = args.access_token;
        this.refresh_token = args.refresh_token;
        this.token_type = args.token_type;
        this.scope = args.scope;
        this.profile = args.profile;
        this.expires_at = args.expires_at;
        this.state = args.userState;
        this.url_state = args.url_state;
    }
    /** Computed number of seconds the access token has remaining. */ get expires_in() {
        if (this.expires_at === void 0) return void 0;
        return this.expires_at - Timer.getEpochTime();
    }
    set expires_in(value) {
        if (value !== void 0) this.expires_at = Math.floor(value) + Timer.getEpochTime();
    }
    /** Computed value indicating if the access token is expired. */ get expired() {
        const expires_in = this.expires_in;
        if (expires_in === void 0) return void 0;
        return expires_in <= 0;
    }
    /** Array representing the parsed values from the `scope`. */ get scopes() {
        var _a, _b;
        return (_b = (_a = this.scope) == null ? void 0 : _a.split(" ")) != null ? _b : [];
    }
    toStorageString() {
        new Logger("User").create("toStorageString");
        return JSON.stringify({
            id_token: this.id_token,
            session_state: this.session_state,
            access_token: this.access_token,
            refresh_token: this.refresh_token,
            token_type: this.token_type,
            scope: this.scope,
            profile: this.profile,
            expires_at: this.expires_at
        });
    }
    static fromStorageString(storageString) {
        Logger.createStatic("User", "fromStorageString");
        return new User(JSON.parse(storageString));
    }
};
// src/navigators/AbstractChildWindow.ts
var messageSource = "oidc-client";
var AbstractChildWindow = class {
    constructor(){
        this._abort = new Event("Window navigation aborted");
        this._disposeHandlers = /* @__PURE__ */ new Set();
        this._window = null;
    }
    async navigate(params) {
        const logger2 = this._logger.create("navigate");
        if (!this._window) throw new Error("Attempted to navigate on a disposed window");
        logger2.debug("setting URL in window");
        this._window.location.replace(params.url);
        const { url, keepOpen } = await new Promise((resolve, reject)=>{
            const listener = (e)=>{
                var _a;
                const data = e.data;
                const origin = (_a = params.scriptOrigin) != null ? _a : window.location.origin;
                if (e.origin !== origin || (data == null ? void 0 : data.source) !== messageSource) return;
                try {
                    const state = UrlUtils.readParams(data.url, params.response_mode).get("state");
                    if (!state) logger2.warn("no state found in response url");
                    if (e.source !== this._window && state !== params.state) return;
                } catch (err) {
                    this._dispose();
                    reject(new Error("Invalid response from window"));
                }
                resolve(data);
            };
            window.addEventListener("message", listener, false);
            this._disposeHandlers.add(()=>window.removeEventListener("message", listener, false));
            this._disposeHandlers.add(this._abort.addHandler((reason)=>{
                this._dispose();
                reject(reason);
            }));
        });
        logger2.debug("got response from window");
        this._dispose();
        if (!keepOpen) this.close();
        return {
            url
        };
    }
    _dispose() {
        this._logger.create("_dispose");
        for (const dispose of this._disposeHandlers)dispose();
        this._disposeHandlers.clear();
    }
    static _notifyParent(parent, url, keepOpen = false, targetOrigin = window.location.origin) {
        parent.postMessage({
            source: messageSource,
            url,
            keepOpen
        }, targetOrigin);
    }
};
// src/UserManagerSettings.ts
var DefaultPopupWindowFeatures = {
    location: false,
    toolbar: false,
    height: 640,
    closePopupWindowAfterInSeconds: -1
};
var DefaultPopupTarget = "_blank";
var DefaultAccessTokenExpiringNotificationTimeInSeconds = 60;
var DefaultCheckSessionIntervalInSeconds = 2;
var DefaultSilentRequestTimeoutInSeconds = 10;
var UserManagerSettingsStore = class extends OidcClientSettingsStore {
    constructor(args){
        const { popup_redirect_uri = args.redirect_uri, popup_post_logout_redirect_uri = args.post_logout_redirect_uri, popupWindowFeatures = DefaultPopupWindowFeatures, popupWindowTarget = DefaultPopupTarget, redirectMethod = "assign", redirectTarget = "self", iframeNotifyParentOrigin = args.iframeNotifyParentOrigin, iframeScriptOrigin = args.iframeScriptOrigin, silent_redirect_uri = args.redirect_uri, silentRequestTimeoutInSeconds = DefaultSilentRequestTimeoutInSeconds, automaticSilentRenew = true, validateSubOnSilentRenew = true, includeIdTokenInSilentRenew = false, monitorSession = false, monitorAnonymousSession = false, checkSessionIntervalInSeconds = DefaultCheckSessionIntervalInSeconds, query_status_response_type = "code", stopCheckSessionOnError = true, revokeTokenTypes = [
            "access_token",
            "refresh_token"
        ], revokeTokensOnSignout = false, includeIdTokenInSilentSignout = false, accessTokenExpiringNotificationTimeInSeconds = DefaultAccessTokenExpiringNotificationTimeInSeconds, userStore } = args;
        super(args);
        this.popup_redirect_uri = popup_redirect_uri;
        this.popup_post_logout_redirect_uri = popup_post_logout_redirect_uri;
        this.popupWindowFeatures = popupWindowFeatures;
        this.popupWindowTarget = popupWindowTarget;
        this.redirectMethod = redirectMethod;
        this.redirectTarget = redirectTarget;
        this.iframeNotifyParentOrigin = iframeNotifyParentOrigin;
        this.iframeScriptOrigin = iframeScriptOrigin;
        this.silent_redirect_uri = silent_redirect_uri;
        this.silentRequestTimeoutInSeconds = silentRequestTimeoutInSeconds;
        this.automaticSilentRenew = automaticSilentRenew;
        this.validateSubOnSilentRenew = validateSubOnSilentRenew;
        this.includeIdTokenInSilentRenew = includeIdTokenInSilentRenew;
        this.monitorSession = monitorSession;
        this.monitorAnonymousSession = monitorAnonymousSession;
        this.checkSessionIntervalInSeconds = checkSessionIntervalInSeconds;
        this.stopCheckSessionOnError = stopCheckSessionOnError;
        this.query_status_response_type = query_status_response_type;
        this.revokeTokenTypes = revokeTokenTypes;
        this.revokeTokensOnSignout = revokeTokensOnSignout;
        this.includeIdTokenInSilentSignout = includeIdTokenInSilentSignout;
        this.accessTokenExpiringNotificationTimeInSeconds = accessTokenExpiringNotificationTimeInSeconds;
        if (userStore) this.userStore = userStore;
        else {
            const store = typeof window !== "undefined" ? window.sessionStorage : new InMemoryWebStorage();
            this.userStore = new WebStorageStateStore({
                store
            });
        }
    }
};
// src/navigators/IFrameWindow.ts
var IFrameWindow = class extends AbstractChildWindow {
    constructor({ silentRequestTimeoutInSeconds = DefaultSilentRequestTimeoutInSeconds }){
        super();
        this._logger = new Logger("IFrameWindow");
        this._timeoutInSeconds = silentRequestTimeoutInSeconds;
        this._frame = IFrameWindow.createHiddenIframe();
        this._window = this._frame.contentWindow;
    }
    static createHiddenIframe() {
        const iframe = window.document.createElement("iframe");
        iframe.style.visibility = "hidden";
        iframe.style.position = "fixed";
        iframe.style.left = "-1000px";
        iframe.style.top = "0";
        iframe.width = "0";
        iframe.height = "0";
        window.document.body.appendChild(iframe);
        return iframe;
    }
    async navigate(params) {
        this._logger.debug("navigate: Using timeout of:", this._timeoutInSeconds);
        const timer = setTimeout(()=>this._abort.raise(new ErrorTimeout("IFrame timed out without a response")), this._timeoutInSeconds * 1e3);
        this._disposeHandlers.add(()=>clearTimeout(timer));
        return await super.navigate(params);
    }
    close() {
        var _a;
        if (this._frame) {
            if (this._frame.parentNode) {
                this._frame.addEventListener("load", (ev)=>{
                    var _a2;
                    const frame = ev.target;
                    (_a2 = frame.parentNode) == null || _a2.removeChild(frame);
                    this._abort.raise(new Error("IFrame removed from DOM"));
                }, true);
                (_a = this._frame.contentWindow) == null || _a.location.replace("about:blank");
            }
            this._frame = null;
        }
        this._window = null;
    }
    static notifyParent(url, targetOrigin) {
        return super._notifyParent(window.parent, url, false, targetOrigin);
    }
};
// src/navigators/IFrameNavigator.ts
var IFrameNavigator = class {
    constructor(_settings){
        this._settings = _settings;
        this._logger = new Logger("IFrameNavigator");
    }
    async prepare({ silentRequestTimeoutInSeconds = this._settings.silentRequestTimeoutInSeconds }) {
        return new IFrameWindow({
            silentRequestTimeoutInSeconds
        });
    }
    async callback(url) {
        this._logger.create("callback");
        IFrameWindow.notifyParent(url, this._settings.iframeNotifyParentOrigin);
    }
};
// src/navigators/PopupWindow.ts
var checkForPopupClosedInterval = 500;
var second = 1e3;
var PopupWindow = class extends AbstractChildWindow {
    constructor({ popupWindowTarget = DefaultPopupTarget, popupWindowFeatures = {} }){
        super();
        this._logger = new Logger("PopupWindow");
        const centeredPopup = PopupUtils.center({
            ...DefaultPopupWindowFeatures,
            ...popupWindowFeatures
        });
        this._window = window.open(void 0, popupWindowTarget, PopupUtils.serialize(centeredPopup));
        if (popupWindowFeatures.closePopupWindowAfterInSeconds && popupWindowFeatures.closePopupWindowAfterInSeconds > 0) setTimeout(()=>{
            if (!this._window || typeof this._window.closed !== "boolean" || this._window.closed) {
                this._abort.raise(new Error("Popup blocked by user"));
                return;
            }
            this.close();
        }, popupWindowFeatures.closePopupWindowAfterInSeconds * second);
    }
    async navigate(params) {
        var _a;
        (_a = this._window) == null || _a.focus();
        const popupClosedInterval = setInterval(()=>{
            if (!this._window || this._window.closed) this._abort.raise(new Error("Popup closed by user"));
        }, checkForPopupClosedInterval);
        this._disposeHandlers.add(()=>clearInterval(popupClosedInterval));
        return await super.navigate(params);
    }
    close() {
        if (this._window) {
            if (!this._window.closed) {
                this._window.close();
                this._abort.raise(new Error("Popup closed"));
            }
        }
        this._window = null;
    }
    static notifyOpener(url, keepOpen) {
        if (!window.opener) throw new Error("No window.opener. Can't complete notification.");
        return super._notifyParent(window.opener, url, keepOpen);
    }
};
// src/navigators/PopupNavigator.ts
var PopupNavigator = class {
    constructor(_settings){
        this._settings = _settings;
        this._logger = new Logger("PopupNavigator");
    }
    async prepare({ popupWindowFeatures = this._settings.popupWindowFeatures, popupWindowTarget = this._settings.popupWindowTarget }) {
        return new PopupWindow({
            popupWindowFeatures,
            popupWindowTarget
        });
    }
    async callback(url, { keepOpen = false }) {
        this._logger.create("callback");
        PopupWindow.notifyOpener(url, keepOpen);
    }
};
// src/navigators/RedirectNavigator.ts
var RedirectNavigator = class {
    constructor(_settings){
        this._settings = _settings;
        this._logger = new Logger("RedirectNavigator");
    }
    async prepare({ redirectMethod = this._settings.redirectMethod, redirectTarget = this._settings.redirectTarget }) {
        var _a;
        this._logger.create("prepare");
        let targetWindow = window.self;
        if (redirectTarget === "top") targetWindow = (_a = window.top) != null ? _a : window.self;
        const redirect = targetWindow.location[redirectMethod].bind(targetWindow.location);
        let abort;
        return {
            navigate: async (params)=>{
                this._logger.create("navigate");
                const promise = new Promise((resolve, reject)=>{
                    abort = reject;
                });
                redirect(params.url);
                return await promise;
            },
            close: ()=>{
                this._logger.create("close");
                abort == null || abort(new Error("Redirect aborted"));
                targetWindow.stop();
            }
        };
    }
    async callback() {
        return;
    }
};
// src/UserManagerEvents.ts
var UserManagerEvents = class extends AccessTokenEvents {
    constructor(settings){
        super({
            expiringNotificationTimeInSeconds: settings.accessTokenExpiringNotificationTimeInSeconds
        });
        this._logger = new Logger("UserManagerEvents");
        this._userLoaded = new Event("User loaded");
        this._userUnloaded = new Event("User unloaded");
        this._silentRenewError = new Event("Silent renew error");
        this._userSignedIn = new Event("User signed in");
        this._userSignedOut = new Event("User signed out");
        this._userSessionChanged = new Event("User session changed");
    }
    load(user, raiseEvent = true) {
        super.load(user);
        if (raiseEvent) this._userLoaded.raise(user);
    }
    unload() {
        super.unload();
        this._userUnloaded.raise();
    }
    /**
   * Add callback: Raised when a user session has been established (or re-established).
   */ addUserLoaded(cb) {
        return this._userLoaded.addHandler(cb);
    }
    /**
   * Remove callback: Raised when a user session has been established (or re-established).
   */ removeUserLoaded(cb) {
        return this._userLoaded.removeHandler(cb);
    }
    /**
   * Add callback: Raised when a user session has been terminated.
   */ addUserUnloaded(cb) {
        return this._userUnloaded.addHandler(cb);
    }
    /**
   * Remove callback: Raised when a user session has been terminated.
   */ removeUserUnloaded(cb) {
        return this._userUnloaded.removeHandler(cb);
    }
    /**
   * Add callback: Raised when the automatic silent renew has failed.
   */ addSilentRenewError(cb) {
        return this._silentRenewError.addHandler(cb);
    }
    /**
   * Remove callback: Raised when the automatic silent renew has failed.
   */ removeSilentRenewError(cb) {
        return this._silentRenewError.removeHandler(cb);
    }
    /**
   * @internal
   */ _raiseSilentRenewError(e) {
        this._silentRenewError.raise(e);
    }
    /**
   * Add callback: Raised when the user is signed in (when `monitorSession` is set).
   * @see {@link UserManagerSettings.monitorSession}
   */ addUserSignedIn(cb) {
        return this._userSignedIn.addHandler(cb);
    }
    /**
   * Remove callback: Raised when the user is signed in (when `monitorSession` is set).
   */ removeUserSignedIn(cb) {
        this._userSignedIn.removeHandler(cb);
    }
    /**
   * @internal
   */ _raiseUserSignedIn() {
        this._userSignedIn.raise();
    }
    /**
   * Add callback: Raised when the user's sign-in status at the OP has changed (when `monitorSession` is set).
   * @see {@link UserManagerSettings.monitorSession}
   */ addUserSignedOut(cb) {
        return this._userSignedOut.addHandler(cb);
    }
    /**
   * Remove callback: Raised when the user's sign-in status at the OP has changed (when `monitorSession` is set).
   */ removeUserSignedOut(cb) {
        this._userSignedOut.removeHandler(cb);
    }
    /**
   * @internal
   */ _raiseUserSignedOut() {
        this._userSignedOut.raise();
    }
    /**
   * Add callback: Raised when the user session changed (when `monitorSession` is set).
   * @see {@link UserManagerSettings.monitorSession}
   */ addUserSessionChanged(cb) {
        return this._userSessionChanged.addHandler(cb);
    }
    /**
   * Remove callback: Raised when the user session changed (when `monitorSession` is set).
   */ removeUserSessionChanged(cb) {
        this._userSessionChanged.removeHandler(cb);
    }
    /**
   * @internal
   */ _raiseUserSessionChanged() {
        this._userSessionChanged.raise();
    }
};
// src/SilentRenewService.ts
var SilentRenewService = class {
    constructor(_userManager){
        this._userManager = _userManager;
        this._logger = new Logger("SilentRenewService");
        this._isStarted = false;
        this._retryTimer = new Timer("Retry Silent Renew");
        this._tokenExpiring = async ()=>{
            const logger2 = this._logger.create("_tokenExpiring");
            try {
                await this._userManager.signinSilent();
                logger2.debug("silent token renewal successful");
            } catch (err) {
                if (err instanceof ErrorTimeout) {
                    logger2.warn("ErrorTimeout from signinSilent:", err, "retry in 5s");
                    this._retryTimer.init(5);
                    return;
                }
                logger2.error("Error from signinSilent:", err);
                this._userManager.events._raiseSilentRenewError(err);
            }
        };
    }
    async start() {
        const logger2 = this._logger.create("start");
        if (!this._isStarted) {
            this._isStarted = true;
            this._userManager.events.addAccessTokenExpiring(this._tokenExpiring);
            this._retryTimer.addHandler(this._tokenExpiring);
            try {
                await this._userManager.getUser();
            } catch (err) {
                logger2.error("getUser error", err);
            }
        }
    }
    stop() {
        if (this._isStarted) {
            this._retryTimer.cancel();
            this._retryTimer.removeHandler(this._tokenExpiring);
            this._userManager.events.removeAccessTokenExpiring(this._tokenExpiring);
            this._isStarted = false;
        }
    }
};
// src/RefreshState.ts
var RefreshState = class {
    constructor(args, resource){
        this.refresh_token = args.refresh_token;
        this.id_token = args.id_token;
        this.session_state = args.session_state;
        this.scope = args.scope;
        this.profile = args.profile;
        this.resource = resource;
        this.data = args.state;
    }
};
// src/UserManager.ts
var UserManager = class {
    constructor(settings, redirectNavigator, popupNavigator, iframeNavigator){
        this._logger = new Logger("UserManager");
        this.settings = new UserManagerSettingsStore(settings);
        this._client = new OidcClient(settings);
        this._redirectNavigator = redirectNavigator != null ? redirectNavigator : new RedirectNavigator(this.settings);
        this._popupNavigator = popupNavigator != null ? popupNavigator : new PopupNavigator(this.settings);
        this._iframeNavigator = iframeNavigator != null ? iframeNavigator : new IFrameNavigator(this.settings);
        this._events = new UserManagerEvents(this.settings);
        this._silentRenewService = new SilentRenewService(this);
        if (this.settings.automaticSilentRenew) this.startSilentRenew();
        this._sessionMonitor = null;
        if (this.settings.monitorSession) this._sessionMonitor = new SessionMonitor(this);
    }
    /** Returns an object used to register for events raised by the `UserManager`. */ get events() {
        return this._events;
    }
    /** Returns an object used to access the metadata configuration of the OIDC provider. */ get metadataService() {
        return this._client.metadataService;
    }
    /**
   * Returns promise to load the `User` object for the currently authenticated user.
   */ async getUser() {
        const logger2 = this._logger.create("getUser");
        const user = await this._loadUser();
        if (user) {
            logger2.info("user loaded");
            this._events.load(user, false);
            return user;
        }
        logger2.info("user not found in storage");
        return null;
    }
    /**
   * Returns promise to remove from any storage the currently authenticated user.
   */ async removeUser() {
        const logger2 = this._logger.create("removeUser");
        await this.storeUser(null);
        logger2.info("user removed from storage");
        this._events.unload();
    }
    /**
   * Returns promise to trigger a redirect of the current window to the authorization endpoint.
   */ async signinRedirect(args = {}) {
        this._logger.create("signinRedirect");
        const { redirectMethod, ...requestArgs } = args;
        const handle = await this._redirectNavigator.prepare({
            redirectMethod
        });
        await this._signinStart({
            request_type: "si:r",
            ...requestArgs
        }, handle);
    }
    /**
   * Returns promise to process response from the authorization endpoint. The result of the promise is the authenticated `User`.
   */ async signinRedirectCallback(url = window.location.href) {
        const logger2 = this._logger.create("signinRedirectCallback");
        const user = await this._signinEnd(url);
        if (user.profile && user.profile.sub) logger2.info("success, signed in subject", user.profile.sub);
        else logger2.info("no subject");
        return user;
    }
    /**
   * Returns promise to process the signin with user/password. The result of the promise is the authenticated `User`.
   *
   * Throws an ErrorResponse in case of wrong authentication.
   */ async signinResourceOwnerCredentials({ username, password, skipUserInfo = false }) {
        const logger2 = this._logger.create("signinResourceOwnerCredential");
        const signinResponse = await this._client.processResourceOwnerPasswordCredentials({
            username,
            password,
            skipUserInfo,
            extraTokenParams: this.settings.extraTokenParams
        });
        logger2.debug("got signin response");
        const user = await this._buildUser(signinResponse);
        if (user.profile && user.profile.sub) logger2.info("success, signed in subject", user.profile.sub);
        else logger2.info("no subject");
        return user;
    }
    /**
   * Returns promise to trigger a request (via a popup window) to the authorization endpoint. The result of the promise is the authenticated `User`.
   */ async signinPopup(args = {}) {
        const logger2 = this._logger.create("signinPopup");
        const { popupWindowFeatures, popupWindowTarget, ...requestArgs } = args;
        const url = this.settings.popup_redirect_uri;
        if (!url) logger2.throw(new Error("No popup_redirect_uri configured"));
        const handle = await this._popupNavigator.prepare({
            popupWindowFeatures,
            popupWindowTarget
        });
        const user = await this._signin({
            request_type: "si:p",
            redirect_uri: url,
            display: "popup",
            ...requestArgs
        }, handle);
        if (user) {
            if (user.profile && user.profile.sub) logger2.info("success, signed in subject", user.profile.sub);
            else logger2.info("no subject");
        }
        return user;
    }
    /**
   * Returns promise to notify the opening window of response from the authorization endpoint.
   */ async signinPopupCallback(url = window.location.href, keepOpen = false) {
        const logger2 = this._logger.create("signinPopupCallback");
        await this._popupNavigator.callback(url, {
            keepOpen
        });
        logger2.info("success");
    }
    /**
   * Returns promise to trigger a silent request (via an iframe) to the authorization endpoint.
   * The result of the promise is the authenticated `User`.
   */ async signinSilent(args = {}) {
        var _a;
        const logger2 = this._logger.create("signinSilent");
        const { silentRequestTimeoutInSeconds, resource, ...requestArgs } = args;
        let user = await this._loadUser();
        if (user == null ? void 0 : user.refresh_token) {
            logger2.debug("using refresh token");
            const state = new RefreshState(user, resource);
            return await this._useRefreshToken(state);
        }
        const url = this.settings.silent_redirect_uri;
        if (!url) logger2.throw(new Error("No silent_redirect_uri configured"));
        let verifySub;
        if (user && this.settings.validateSubOnSilentRenew) {
            logger2.debug("subject prior to silent renew:", user.profile.sub);
            verifySub = user.profile.sub;
        }
        const handle = await this._iframeNavigator.prepare({
            silentRequestTimeoutInSeconds
        });
        user = await this._signin({
            request_type: "si:s",
            redirect_uri: url,
            prompt: "none",
            id_token_hint: this.settings.includeIdTokenInSilentRenew ? user == null ? void 0 : user.id_token : void 0,
            ...requestArgs
        }, handle, verifySub);
        if (user) {
            if ((_a = user.profile) == null ? void 0 : _a.sub) logger2.info("success, signed in subject", user.profile.sub);
            else logger2.info("no subject");
        }
        return user;
    }
    async _useRefreshToken(state) {
        const response = await this._client.useRefreshToken({
            state,
            timeoutInSeconds: this.settings.silentRequestTimeoutInSeconds
        });
        const user = new User({
            ...state,
            ...response
        });
        await this.storeUser(user);
        this._events.load(user);
        return user;
    }
    /**
   * Returns promise to notify the parent window of response from the authorization endpoint.
   */ async signinSilentCallback(url = window.location.href) {
        const logger2 = this._logger.create("signinSilentCallback");
        await this._iframeNavigator.callback(url);
        logger2.info("success");
    }
    async signinCallback(url = window.location.href) {
        const { state } = await this._client.readSigninResponseState(url);
        switch(state.request_type){
            case "si:r":
                return await this.signinRedirectCallback(url);
            case "si:p":
                return await this.signinPopupCallback(url);
            case "si:s":
                return await this.signinSilentCallback(url);
            default:
                throw new Error("invalid response_type in state");
        }
    }
    async signoutCallback(url = window.location.href, keepOpen = false) {
        const { state } = await this._client.readSignoutResponseState(url);
        if (!state) return;
        switch(state.request_type){
            case "so:r":
                await this.signoutRedirectCallback(url);
                break;
            case "so:p":
                await this.signoutPopupCallback(url, keepOpen);
                break;
            case "so:s":
                await this.signoutSilentCallback(url);
                break;
            default:
                throw new Error("invalid response_type in state");
        }
    }
    /**
   * Returns promise to query OP for user's current signin status. Returns object with session_state and subject identifier.
   */ async querySessionStatus(args = {}) {
        const logger2 = this._logger.create("querySessionStatus");
        const { silentRequestTimeoutInSeconds, ...requestArgs } = args;
        const url = this.settings.silent_redirect_uri;
        if (!url) logger2.throw(new Error("No silent_redirect_uri configured"));
        const user = await this._loadUser();
        const handle = await this._iframeNavigator.prepare({
            silentRequestTimeoutInSeconds
        });
        const navResponse = await this._signinStart({
            request_type: "si:s",
            // this acts like a signin silent
            redirect_uri: url,
            prompt: "none",
            id_token_hint: this.settings.includeIdTokenInSilentRenew ? user == null ? void 0 : user.id_token : void 0,
            response_type: this.settings.query_status_response_type,
            scope: "openid",
            skipUserInfo: true,
            ...requestArgs
        }, handle);
        try {
            const signinResponse = await this._client.processSigninResponse(navResponse.url);
            logger2.debug("got signin response");
            if (signinResponse.session_state && signinResponse.profile.sub) {
                logger2.info("success for subject", signinResponse.profile.sub);
                return {
                    session_state: signinResponse.session_state,
                    sub: signinResponse.profile.sub,
                    sid: signinResponse.profile.sid
                };
            }
            logger2.info("success, user not authenticated");
            return null;
        } catch (err) {
            if (this.settings.monitorAnonymousSession && err instanceof ErrorResponse) switch(err.error){
                case "login_required":
                case "consent_required":
                case "interaction_required":
                case "account_selection_required":
                    logger2.info("success for anonymous user");
                    return {
                        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
                        session_state: err.session_state
                    };
            }
            throw err;
        }
    }
    async _signin(args, handle, verifySub) {
        const navResponse = await this._signinStart(args, handle);
        return await this._signinEnd(navResponse.url, verifySub);
    }
    async _signinStart(args, handle) {
        const logger2 = this._logger.create("_signinStart");
        try {
            const signinRequest = await this._client.createSigninRequest(args);
            logger2.debug("got signin request");
            return await handle.navigate({
                url: signinRequest.url,
                state: signinRequest.state.id,
                response_mode: signinRequest.state.response_mode,
                scriptOrigin: this.settings.iframeScriptOrigin
            });
        } catch (err) {
            logger2.debug("error after preparing navigator, closing navigator window");
            handle.close();
            throw err;
        }
    }
    async _signinEnd(url, verifySub) {
        const logger2 = this._logger.create("_signinEnd");
        const signinResponse = await this._client.processSigninResponse(url);
        logger2.debug("got signin response");
        const user = await this._buildUser(signinResponse, verifySub);
        return user;
    }
    async _buildUser(signinResponse, verifySub) {
        const logger2 = this._logger.create("_buildUser");
        const user = new User(signinResponse);
        if (verifySub) {
            if (verifySub !== user.profile.sub) {
                logger2.debug("current user does not match user returned from signin. sub from signin:", user.profile.sub);
                throw new ErrorResponse({
                    ...signinResponse,
                    error: "login_required"
                });
            }
            logger2.debug("current user matches user returned from signin");
        }
        await this.storeUser(user);
        logger2.debug("user stored");
        this._events.load(user);
        return user;
    }
    /**
   * Returns promise to trigger a redirect of the current window to the end session endpoint.
   */ async signoutRedirect(args = {}) {
        const logger2 = this._logger.create("signoutRedirect");
        const { redirectMethod, ...requestArgs } = args;
        const handle = await this._redirectNavigator.prepare({
            redirectMethod
        });
        await this._signoutStart({
            request_type: "so:r",
            post_logout_redirect_uri: this.settings.post_logout_redirect_uri,
            ...requestArgs
        }, handle);
        logger2.info("success");
    }
    /**
   * Returns promise to process response from the end session endpoint.
   */ async signoutRedirectCallback(url = window.location.href) {
        const logger2 = this._logger.create("signoutRedirectCallback");
        const response = await this._signoutEnd(url);
        logger2.info("success");
        return response;
    }
    /**
   * Returns promise to trigger a redirect of a popup window window to the end session endpoint.
   */ async signoutPopup(args = {}) {
        const logger2 = this._logger.create("signoutPopup");
        const { popupWindowFeatures, popupWindowTarget, ...requestArgs } = args;
        const url = this.settings.popup_post_logout_redirect_uri;
        const handle = await this._popupNavigator.prepare({
            popupWindowFeatures,
            popupWindowTarget
        });
        await this._signout({
            request_type: "so:p",
            post_logout_redirect_uri: url,
            // we're putting a dummy entry in here because we
            // need a unique id from the state for notification
            // to the parent window, which is necessary if we
            // plan to return back to the client after signout
            // and so we can close the popup after signout
            state: url == null ? void 0 : {},
            ...requestArgs
        }, handle);
        logger2.info("success");
    }
    /**
   * Returns promise to process response from the end session endpoint from a popup window.
   */ async signoutPopupCallback(url = window.location.href, keepOpen = false) {
        const logger2 = this._logger.create("signoutPopupCallback");
        await this._popupNavigator.callback(url, {
            keepOpen
        });
        logger2.info("success");
    }
    async _signout(args, handle) {
        const navResponse = await this._signoutStart(args, handle);
        return await this._signoutEnd(navResponse.url);
    }
    async _signoutStart(args = {}, handle) {
        var _a;
        const logger2 = this._logger.create("_signoutStart");
        try {
            const user = await this._loadUser();
            logger2.debug("loaded current user from storage");
            if (this.settings.revokeTokensOnSignout) await this._revokeInternal(user);
            const id_token = args.id_token_hint || user && user.id_token;
            if (id_token) {
                logger2.debug("setting id_token_hint in signout request");
                args.id_token_hint = id_token;
            }
            await this.removeUser();
            logger2.debug("user removed, creating signout request");
            const signoutRequest = await this._client.createSignoutRequest(args);
            logger2.debug("got signout request");
            return await handle.navigate({
                url: signoutRequest.url,
                state: (_a = signoutRequest.state) == null ? void 0 : _a.id,
                scriptOrigin: this.settings.iframeScriptOrigin
            });
        } catch (err) {
            logger2.debug("error after preparing navigator, closing navigator window");
            handle.close();
            throw err;
        }
    }
    async _signoutEnd(url) {
        const logger2 = this._logger.create("_signoutEnd");
        const signoutResponse = await this._client.processSignoutResponse(url);
        logger2.debug("got signout response");
        return signoutResponse;
    }
    /**
   * Returns promise to trigger a silent request (via an iframe) to the end session endpoint.
   */ async signoutSilent(args = {}) {
        var _a;
        const logger2 = this._logger.create("signoutSilent");
        const { silentRequestTimeoutInSeconds, ...requestArgs } = args;
        const id_token_hint = this.settings.includeIdTokenInSilentSignout ? (_a = await this._loadUser()) == null ? void 0 : _a.id_token : void 0;
        const url = this.settings.popup_post_logout_redirect_uri;
        const handle = await this._iframeNavigator.prepare({
            silentRequestTimeoutInSeconds
        });
        await this._signout({
            request_type: "so:s",
            post_logout_redirect_uri: url,
            id_token_hint,
            ...requestArgs
        }, handle);
        logger2.info("success");
    }
    /**
   * Returns promise to notify the parent window of response from the end session endpoint.
   */ async signoutSilentCallback(url = window.location.href) {
        const logger2 = this._logger.create("signoutSilentCallback");
        await this._iframeNavigator.callback(url);
        logger2.info("success");
    }
    async revokeTokens(types) {
        const user = await this._loadUser();
        await this._revokeInternal(user, types);
    }
    async _revokeInternal(user, types = this.settings.revokeTokenTypes) {
        const logger2 = this._logger.create("_revokeInternal");
        if (!user) return;
        const typesPresent = types.filter((type)=>typeof user[type] === "string");
        if (!typesPresent.length) {
            logger2.debug("no need to revoke due to no token(s)");
            return;
        }
        for (const type of typesPresent){
            await this._client.revokeToken(user[type], // eslint-disable-line @typescript-eslint/no-non-null-assertion
            type);
            logger2.info(`${type} revoked successfully`);
            if (type !== "access_token") user[type] = null;
        }
        await this.storeUser(user);
        logger2.debug("user stored");
        this._events.load(user);
    }
    /**
   * Enables silent renew for the `UserManager`.
   */ startSilentRenew() {
        this._logger.create("startSilentRenew");
        this._silentRenewService.start();
    }
    /**
   * Disables silent renew for the `UserManager`.
   */ stopSilentRenew() {
        this._silentRenewService.stop();
    }
    get _userStoreKey() {
        return `user:${this.settings.authority}:${this.settings.client_id}`;
    }
    async _loadUser() {
        const logger2 = this._logger.create("_loadUser");
        const storageString = await this.settings.userStore.get(this._userStoreKey);
        if (storageString) {
            logger2.debug("user storageString loaded");
            return User.fromStorageString(storageString);
        }
        logger2.debug("no user storageString");
        return null;
    }
    async storeUser(user) {
        const logger2 = this._logger.create("storeUser");
        if (user) {
            logger2.debug("storing user");
            const storageString = user.toStorageString();
            await this.settings.userStore.set(this._userStoreKey, storageString);
        } else {
            this._logger.debug("removing user");
            await this.settings.userStore.remove(this._userStoreKey);
        }
    }
    /**
   * Removes stale state entries in storage for incomplete authorize requests.
   */ async clearStaleState() {
        await this._client.clearStaleState();
    }
};
// package.json
var version = "2.4.0";
// src/Version.ts
var Version = version;

},{"cd65f2846f9a9917":"gcdtm","b081c80cbcca67d0":"lNj7D","69a1441ed613820e":"1XZVI","46685f198d718556":"exkTk","3455b80cc963b26":"ljM1w"}],"gcdtm":[function(require,module,exports) {
var global = arguments[3];
(function(root, factory) {
    // CommonJS
    module.exports = exports = factory();
})(this, function() {
    /*globals window, global, require*/ /**
	 * CryptoJS core components.
	 */ var CryptoJS = CryptoJS || function(Math1, undefined) {
        var crypto;
        // Native crypto from window (Browser)
        if (typeof window !== "undefined" && window.crypto) crypto = window.crypto;
        // Native crypto in web worker (Browser)
        if (typeof self !== "undefined" && self.crypto) crypto = self.crypto;
        // Native crypto from worker
        if (typeof globalThis !== "undefined" && globalThis.crypto) crypto = globalThis.crypto;
        // Native (experimental IE 11) crypto from window (Browser)
        if (!crypto && typeof window !== "undefined" && window.msCrypto) crypto = window.msCrypto;
        // Native crypto from global (NodeJS)
        if (!crypto && typeof global !== "undefined" && global.crypto) crypto = global.crypto;
        // Native crypto import via require (NodeJS)
        if (!crypto && true) try {
            crypto = require("b7760e5f0b7216d4");
        } catch (err) {}
        /*
	     * Cryptographically secure pseudorandom number generator
	     *
	     * As Math.random() is cryptographically not safe to use
	     */ var cryptoSecureRandomInt = function() {
            if (crypto) {
                // Use getRandomValues method (Browser)
                if (typeof crypto.getRandomValues === "function") try {
                    return crypto.getRandomValues(new Uint32Array(1))[0];
                } catch (err) {}
                // Use randomBytes method (NodeJS)
                if (typeof crypto.randomBytes === "function") try {
                    return crypto.randomBytes(4).readInt32LE();
                } catch (err) {}
            }
            throw new Error("Native crypto module could not be used to get secure random number.");
        };
        /*
	     * Local polyfill of Object.create

	     */ var create = Object.create || function() {
            function F() {}
            return function(obj) {
                var subtype;
                F.prototype = obj;
                subtype = new F();
                F.prototype = null;
                return subtype;
            };
        }();
        /**
	     * CryptoJS namespace.
	     */ var C = {};
        /**
	     * Library namespace.
	     */ var C_lib = C.lib = {};
        /**
	     * Base object for prototypal inheritance.
	     */ var Base = C_lib.Base = function() {
            return {
                /**
	             * Creates a new object that inherits from this object.
	             *
	             * @param {Object} overrides Properties to copy into the new object.
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         field: 'value',
	             *
	             *         method: function () {
	             *         }
	             *     });
	             */ extend: function(overrides) {
                    // Spawn
                    var subtype = create(this);
                    // Augment
                    if (overrides) subtype.mixIn(overrides);
                    // Create default initializer
                    if (!subtype.hasOwnProperty("init") || this.init === subtype.init) subtype.init = function() {
                        subtype.$super.init.apply(this, arguments);
                    };
                    // Initializer's prototype is the subtype object
                    subtype.init.prototype = subtype;
                    // Reference supertype
                    subtype.$super = this;
                    return subtype;
                },
                /**
	             * Extends this object and runs the init method.
	             * Arguments to create() will be passed to init().
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var instance = MyType.create();
	             */ create: function() {
                    var instance = this.extend();
                    instance.init.apply(instance, arguments);
                    return instance;
                },
                /**
	             * Initializes a newly created object.
	             * Override this method to add some logic when your objects are created.
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         init: function () {
	             *             // ...
	             *         }
	             *     });
	             */ init: function() {},
                /**
	             * Copies properties into this object.
	             *
	             * @param {Object} properties The properties to mix in.
	             *
	             * @example
	             *
	             *     MyType.mixIn({
	             *         field: 'value'
	             *     });
	             */ mixIn: function(properties) {
                    for(var propertyName in properties)if (properties.hasOwnProperty(propertyName)) this[propertyName] = properties[propertyName];
                    // IE won't copy toString using the loop above
                    if (properties.hasOwnProperty("toString")) this.toString = properties.toString;
                },
                /**
	             * Creates a copy of this object.
	             *
	             * @return {Object} The clone.
	             *
	             * @example
	             *
	             *     var clone = instance.clone();
	             */ clone: function() {
                    return this.init.prototype.extend(this);
                }
            };
        }();
        /**
	     * An array of 32-bit words.
	     *
	     * @property {Array} words The array of 32-bit words.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */ var WordArray = C_lib.WordArray = Base.extend({
            /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of 32-bit words.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.create();
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
	         */ init: function(words, sigBytes) {
                words = this.words = words || [];
                if (sigBytes != undefined) this.sigBytes = sigBytes;
                else this.sigBytes = words.length * 4;
            },
            /**
	         * Converts this word array to a string.
	         *
	         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
	         *
	         * @return {string} The stringified word array.
	         *
	         * @example
	         *
	         *     var string = wordArray + '';
	         *     var string = wordArray.toString();
	         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
	         */ toString: function(encoder) {
                return (encoder || Hex).stringify(this);
            },
            /**
	         * Concatenates a word array to this word array.
	         *
	         * @param {WordArray} wordArray The word array to append.
	         *
	         * @return {WordArray} This word array.
	         *
	         * @example
	         *
	         *     wordArray1.concat(wordArray2);
	         */ concat: function(wordArray) {
                // Shortcuts
                var thisWords = this.words;
                var thatWords = wordArray.words;
                var thisSigBytes = this.sigBytes;
                var thatSigBytes = wordArray.sigBytes;
                // Clamp excess bits
                this.clamp();
                // Concat
                if (thisSigBytes % 4) // Copy one byte at a time
                for(var i = 0; i < thatSigBytes; i++){
                    var thatByte = thatWords[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
                    thisWords[thisSigBytes + i >>> 2] |= thatByte << 24 - (thisSigBytes + i) % 4 * 8;
                }
                else // Copy one word at a time
                for(var j = 0; j < thatSigBytes; j += 4)thisWords[thisSigBytes + j >>> 2] = thatWords[j >>> 2];
                this.sigBytes += thatSigBytes;
                // Chainable
                return this;
            },
            /**
	         * Removes insignificant bits.
	         *
	         * @example
	         *
	         *     wordArray.clamp();
	         */ clamp: function() {
                // Shortcuts
                var words = this.words;
                var sigBytes = this.sigBytes;
                // Clamp
                words[sigBytes >>> 2] &= 0xffffffff << 32 - sigBytes % 4 * 8;
                words.length = Math1.ceil(sigBytes / 4);
            },
            /**
	         * Creates a copy of this word array.
	         *
	         * @return {WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = wordArray.clone();
	         */ clone: function() {
                var clone = Base.clone.call(this);
                clone.words = this.words.slice(0);
                return clone;
            },
            /**
	         * Creates a word array filled with random bytes.
	         *
	         * @param {number} nBytes The number of random bytes to generate.
	         *
	         * @return {WordArray} The random word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.random(16);
	         */ random: function(nBytes) {
                var words = [];
                for(var i = 0; i < nBytes; i += 4)words.push(cryptoSecureRandomInt());
                return new WordArray.init(words, nBytes);
            }
        });
        /**
	     * Encoder namespace.
	     */ var C_enc = C.enc = {};
        /**
	     * Hex encoding strategy.
	     */ var Hex = C_enc.Hex = {
            /**
	         * Converts a word array to a hex string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The hex string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
	         */ stringify: function(wordArray) {
                // Shortcuts
                var words = wordArray.words;
                var sigBytes = wordArray.sigBytes;
                // Convert
                var hexChars = [];
                for(var i = 0; i < sigBytes; i++){
                    var bite = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
                    hexChars.push((bite >>> 4).toString(16));
                    hexChars.push((bite & 0x0f).toString(16));
                }
                return hexChars.join("");
            },
            /**
	         * Converts a hex string to a word array.
	         *
	         * @param {string} hexStr The hex string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
	         */ parse: function(hexStr) {
                // Shortcut
                var hexStrLength = hexStr.length;
                // Convert
                var words = [];
                for(var i = 0; i < hexStrLength; i += 2)words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << 24 - i % 8 * 4;
                return new WordArray.init(words, hexStrLength / 2);
            }
        };
        /**
	     * Latin1 encoding strategy.
	     */ var Latin1 = C_enc.Latin1 = {
            /**
	         * Converts a word array to a Latin1 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Latin1 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
	         */ stringify: function(wordArray) {
                // Shortcuts
                var words = wordArray.words;
                var sigBytes = wordArray.sigBytes;
                // Convert
                var latin1Chars = [];
                for(var i = 0; i < sigBytes; i++){
                    var bite = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
                    latin1Chars.push(String.fromCharCode(bite));
                }
                return latin1Chars.join("");
            },
            /**
	         * Converts a Latin1 string to a word array.
	         *
	         * @param {string} latin1Str The Latin1 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
	         */ parse: function(latin1Str) {
                // Shortcut
                var latin1StrLength = latin1Str.length;
                // Convert
                var words = [];
                for(var i = 0; i < latin1StrLength; i++)words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << 24 - i % 4 * 8;
                return new WordArray.init(words, latin1StrLength);
            }
        };
        /**
	     * UTF-8 encoding strategy.
	     */ var Utf8 = C_enc.Utf8 = {
            /**
	         * Converts a word array to a UTF-8 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-8 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
	         */ stringify: function(wordArray) {
                try {
                    return decodeURIComponent(escape(Latin1.stringify(wordArray)));
                } catch (e) {
                    throw new Error("Malformed UTF-8 data");
                }
            },
            /**
	         * Converts a UTF-8 string to a word array.
	         *
	         * @param {string} utf8Str The UTF-8 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
	         */ parse: function(utf8Str) {
                return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
            }
        };
        /**
	     * Abstract buffered block algorithm template.
	     *
	     * The property blockSize must be implemented in a concrete subtype.
	     *
	     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
	     */ var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
            /**
	         * Resets this block algorithm's data buffer to its initial state.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm.reset();
	         */ reset: function() {
                // Initial values
                this._data = new WordArray.init();
                this._nDataBytes = 0;
            },
            /**
	         * Adds new data to this block algorithm's buffer.
	         *
	         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm._append('data');
	         *     bufferedBlockAlgorithm._append(wordArray);
	         */ _append: function(data) {
                // Convert string to WordArray, else assume WordArray already
                if (typeof data == "string") data = Utf8.parse(data);
                // Append
                this._data.concat(data);
                this._nDataBytes += data.sigBytes;
            },
            /**
	         * Processes available data blocks.
	         *
	         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
	         *
	         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
	         *
	         * @return {WordArray} The processed data.
	         *
	         * @example
	         *
	         *     var processedData = bufferedBlockAlgorithm._process();
	         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
	         */ _process: function(doFlush) {
                var processedWords;
                // Shortcuts
                var data = this._data;
                var dataWords = data.words;
                var dataSigBytes = data.sigBytes;
                var blockSize = this.blockSize;
                var blockSizeBytes = blockSize * 4;
                // Count blocks ready
                var nBlocksReady = dataSigBytes / blockSizeBytes;
                if (doFlush) // Round up to include partial blocks
                nBlocksReady = Math1.ceil(nBlocksReady);
                else // Round down to include only full blocks,
                // less the number of blocks that must remain in the buffer
                nBlocksReady = Math1.max((nBlocksReady | 0) - this._minBufferSize, 0);
                // Count words ready
                var nWordsReady = nBlocksReady * blockSize;
                // Count bytes ready
                var nBytesReady = Math1.min(nWordsReady * 4, dataSigBytes);
                // Process blocks
                if (nWordsReady) {
                    for(var offset = 0; offset < nWordsReady; offset += blockSize)// Perform concrete-algorithm logic
                    this._doProcessBlock(dataWords, offset);
                    // Remove processed words
                    processedWords = dataWords.splice(0, nWordsReady);
                    data.sigBytes -= nBytesReady;
                }
                // Return processed words
                return new WordArray.init(processedWords, nBytesReady);
            },
            /**
	         * Creates a copy of this object.
	         *
	         * @return {Object} The clone.
	         *
	         * @example
	         *
	         *     var clone = bufferedBlockAlgorithm.clone();
	         */ clone: function() {
                var clone = Base.clone.call(this);
                clone._data = this._data.clone();
                return clone;
            },
            _minBufferSize: 0
        });
        /**
	     * Abstract hasher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
	     */ var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
            /**
	         * Configuration options.
	         */ cfg: Base.extend(),
            /**
	         * Initializes a newly created hasher.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
	         *
	         * @example
	         *
	         *     var hasher = CryptoJS.algo.SHA256.create();
	         */ init: function(cfg) {
                // Apply config defaults
                this.cfg = this.cfg.extend(cfg);
                // Set initial values
                this.reset();
            },
            /**
	         * Resets this hasher to its initial state.
	         *
	         * @example
	         *
	         *     hasher.reset();
	         */ reset: function() {
                // Reset data buffer
                BufferedBlockAlgorithm.reset.call(this);
                // Perform concrete-hasher logic
                this._doReset();
            },
            /**
	         * Updates this hasher with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {Hasher} This hasher.
	         *
	         * @example
	         *
	         *     hasher.update('message');
	         *     hasher.update(wordArray);
	         */ update: function(messageUpdate) {
                // Append
                this._append(messageUpdate);
                // Update the hash
                this._process();
                // Chainable
                return this;
            },
            /**
	         * Finalizes the hash computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The hash.
	         *
	         * @example
	         *
	         *     var hash = hasher.finalize();
	         *     var hash = hasher.finalize('message');
	         *     var hash = hasher.finalize(wordArray);
	         */ finalize: function(messageUpdate) {
                // Final message update
                if (messageUpdate) this._append(messageUpdate);
                // Perform concrete-hasher logic
                var hash = this._doFinalize();
                return hash;
            },
            blockSize: 16,
            /**
	         * Creates a shortcut function to a hasher's object interface.
	         *
	         * @param {Hasher} hasher The hasher to create a helper for.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
	         */ _createHelper: function(hasher) {
                return function(message, cfg) {
                    return new hasher.init(cfg).finalize(message);
                };
            },
            /**
	         * Creates a shortcut function to the HMAC's object interface.
	         *
	         * @param {Hasher} hasher The hasher to use in this HMAC helper.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
	         */ _createHmacHelper: function(hasher) {
                return function(message, key) {
                    return new C_algo.HMAC.init(hasher, key).finalize(message);
                };
            }
        });
        /**
	     * Algorithm namespace.
	     */ var C_algo = C.algo = {};
        return C;
    }(Math);
    return CryptoJS;
});

},{"b7760e5f0b7216d4":"jhUEF"}],"jhUEF":[function(require,module,exports) {
"use strict";

},{}],"lNj7D":[function(require,module,exports) {
(function(root, factory) {
    // CommonJS
    module.exports = exports = factory(require("cd9e8447cb14a145"));
})(this, function(CryptoJS) {
    (function(Math1) {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var WordArray = C_lib.WordArray;
        var Hasher = C_lib.Hasher;
        var C_algo = C.algo;
        // Initialization and round constants tables
        var H = [];
        var K = [];
        // Compute constants
        (function() {
            function isPrime(n) {
                var sqrtN = Math1.sqrt(n);
                for(var factor = 2; factor <= sqrtN; factor++){
                    if (!(n % factor)) return false;
                }
                return true;
            }
            function getFractionalBits(n) {
                return (n - (n | 0)) * 0x100000000 | 0;
            }
            var n = 2;
            var nPrime = 0;
            while(nPrime < 64){
                if (isPrime(n)) {
                    if (nPrime < 8) H[nPrime] = getFractionalBits(Math1.pow(n, 0.5));
                    K[nPrime] = getFractionalBits(Math1.pow(n, 1 / 3));
                    nPrime++;
                }
                n++;
            }
        })();
        // Reusable object
        var W = [];
        /**
	     * SHA-256 hash algorithm.
	     */ var SHA256 = C_algo.SHA256 = Hasher.extend({
            _doReset: function() {
                this._hash = new WordArray.init(H.slice(0));
            },
            _doProcessBlock: function(M, offset) {
                // Shortcut
                var H = this._hash.words;
                // Working variables
                var a = H[0];
                var b = H[1];
                var c = H[2];
                var d = H[3];
                var e = H[4];
                var f = H[5];
                var g = H[6];
                var h = H[7];
                // Computation
                for(var i = 0; i < 64; i++){
                    if (i < 16) W[i] = M[offset + i] | 0;
                    else {
                        var gamma0x = W[i - 15];
                        var gamma0 = (gamma0x << 25 | gamma0x >>> 7) ^ (gamma0x << 14 | gamma0x >>> 18) ^ gamma0x >>> 3;
                        var gamma1x = W[i - 2];
                        var gamma1 = (gamma1x << 15 | gamma1x >>> 17) ^ (gamma1x << 13 | gamma1x >>> 19) ^ gamma1x >>> 10;
                        W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
                    }
                    var ch = e & f ^ ~e & g;
                    var maj = a & b ^ a & c ^ b & c;
                    var sigma0 = (a << 30 | a >>> 2) ^ (a << 19 | a >>> 13) ^ (a << 10 | a >>> 22);
                    var sigma1 = (e << 26 | e >>> 6) ^ (e << 21 | e >>> 11) ^ (e << 7 | e >>> 25);
                    var t1 = h + sigma1 + ch + K[i] + W[i];
                    var t2 = sigma0 + maj;
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1 | 0;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2 | 0;
                }
                // Intermediate hash value
                H[0] = H[0] + a | 0;
                H[1] = H[1] + b | 0;
                H[2] = H[2] + c | 0;
                H[3] = H[3] + d | 0;
                H[4] = H[4] + e | 0;
                H[5] = H[5] + f | 0;
                H[6] = H[6] + g | 0;
                H[7] = H[7] + h | 0;
            },
            _doFinalize: function() {
                // Shortcuts
                var data = this._data;
                var dataWords = data.words;
                var nBitsTotal = this._nDataBytes * 8;
                var nBitsLeft = data.sigBytes * 8;
                // Add padding
                dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
                dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = Math1.floor(nBitsTotal / 0x100000000);
                dataWords[(nBitsLeft + 64 >>> 9 << 4) + 15] = nBitsTotal;
                data.sigBytes = dataWords.length * 4;
                // Hash final blocks
                this._process();
                // Return final computed hash
                return this._hash;
            },
            clone: function() {
                var clone = Hasher.clone.call(this);
                clone._hash = this._hash.clone();
                return clone;
            }
        });
        /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA256('message');
	     *     var hash = CryptoJS.SHA256(wordArray);
	     */ C.SHA256 = Hasher._createHelper(SHA256);
        /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA256(message, key);
	     */ C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
    })(Math);
    return CryptoJS.SHA256;
});

},{"cd9e8447cb14a145":"gcdtm"}],"1XZVI":[function(require,module,exports) {
(function(root, factory) {
    // CommonJS
    module.exports = exports = factory(require("6c67d43f833ec62e"));
})(this, function(CryptoJS) {
    (function() {
        // Shortcuts
        var C = CryptoJS;
        var C_lib = C.lib;
        var WordArray = C_lib.WordArray;
        var C_enc = C.enc;
        /**
	     * Base64 encoding strategy.
	     */ var Base64 = C_enc.Base64 = {
            /**
	         * Converts a word array to a Base64 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Base64 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
	         */ stringify: function(wordArray) {
                // Shortcuts
                var words = wordArray.words;
                var sigBytes = wordArray.sigBytes;
                var map = this._map;
                // Clamp excess bits
                wordArray.clamp();
                // Convert
                var base64Chars = [];
                for(var i = 0; i < sigBytes; i += 3){
                    var byte1 = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
                    var byte2 = words[i + 1 >>> 2] >>> 24 - (i + 1) % 4 * 8 & 0xff;
                    var byte3 = words[i + 2 >>> 2] >>> 24 - (i + 2) % 4 * 8 & 0xff;
                    var triplet = byte1 << 16 | byte2 << 8 | byte3;
                    for(var j = 0; j < 4 && i + j * 0.75 < sigBytes; j++)base64Chars.push(map.charAt(triplet >>> 6 * (3 - j) & 0x3f));
                }
                // Add padding
                var paddingChar = map.charAt(64);
                if (paddingChar) while(base64Chars.length % 4)base64Chars.push(paddingChar);
                return base64Chars.join("");
            },
            /**
	         * Converts a Base64 string to a word array.
	         *
	         * @param {string} base64Str The Base64 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
	         */ parse: function(base64Str) {
                // Shortcuts
                var base64StrLength = base64Str.length;
                var map = this._map;
                var reverseMap = this._reverseMap;
                if (!reverseMap) {
                    reverseMap = this._reverseMap = [];
                    for(var j = 0; j < map.length; j++)reverseMap[map.charCodeAt(j)] = j;
                }
                // Ignore padding
                var paddingChar = map.charAt(64);
                if (paddingChar) {
                    var paddingIndex = base64Str.indexOf(paddingChar);
                    if (paddingIndex !== -1) base64StrLength = paddingIndex;
                }
                // Convert
                return parseLoop(base64Str, base64StrLength, reverseMap);
            },
            _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        };
        function parseLoop(base64Str, base64StrLength, reverseMap) {
            var words = [];
            var nBytes = 0;
            for(var i = 0; i < base64StrLength; i++)if (i % 4) {
                var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << i % 4 * 2;
                var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> 6 - i % 4 * 2;
                var bitsCombined = bits1 | bits2;
                words[nBytes >>> 2] |= bitsCombined << 24 - nBytes % 4 * 8;
                nBytes++;
            }
            return WordArray.create(words, nBytes);
        }
    })();
    return CryptoJS.enc.Base64;
});

},{"6c67d43f833ec62e":"gcdtm"}],"exkTk":[function(require,module,exports) {
(function(root, factory) {
    // CommonJS
    module.exports = exports = factory(require("7286559b12995fed"));
})(this, function(CryptoJS) {
    return CryptoJS.enc.Utf8;
});

},{"7286559b12995fed":"gcdtm"}],"ljM1w":[function(require,module,exports) {
var parcelHelpers = require("@parcel/transformer-js/src/esmodule-helpers.js");
parcelHelpers.defineInteropFlag(exports);
parcelHelpers.export(exports, "InvalidTokenError", ()=>n);
function e(e) {
    this.message = e;
}
e.prototype = new Error, e.prototype.name = "InvalidCharacterError";
var r = "undefined" != typeof window && window.atob && window.atob.bind(window) || function(r) {
    var t = String(r).replace(/=+$/, "");
    if (t.length % 4 == 1) throw new e("'atob' failed: The string to be decoded is not correctly encoded.");
    for(var n, o, a = 0, i = 0, c = ""; o = t.charAt(i++); ~o && (n = a % 4 ? 64 * n + o : o, a++ % 4) && (c += String.fromCharCode(255 & n >> (-2 * a & 6))))o = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(o);
    return c;
};
function t(e) {
    var t = e.replace(/-/g, "+").replace(/_/g, "/");
    switch(t.length % 4){
        case 0:
            break;
        case 2:
            t += "==";
            break;
        case 3:
            t += "=";
            break;
        default:
            throw "Illegal base64url string!";
    }
    try {
        return function(e) {
            return decodeURIComponent(r(e).replace(/(.)/g, function(e, r) {
                var t = r.charCodeAt(0).toString(16).toUpperCase();
                return t.length < 2 && (t = "0" + t), "%" + t;
            }));
        }(t);
    } catch (e) {
        return r(t);
    }
}
function n(e) {
    this.message = e;
}
function o(e, r) {
    if ("string" != typeof e) throw new n("Invalid token specified");
    var o = !0 === (r = r || {}).header ? 0 : 1;
    try {
        return JSON.parse(t(e.split(".")[o]));
    } catch (e) {
        throw new n("Invalid token specified: " + e.message);
    }
}
n.prototype = new Error, n.prototype.name = "InvalidTokenError";
exports.default = o;

},{"@parcel/transformer-js/src/esmodule-helpers.js":"gkKU3"}],"gkKU3":[function(require,module,exports) {
exports.interopDefault = function(a) {
    return a && a.__esModule ? a : {
        default: a
    };
};
exports.defineInteropFlag = function(a) {
    Object.defineProperty(a, "__esModule", {
        value: true
    });
};
exports.exportAll = function(source, dest) {
    Object.keys(source).forEach(function(key) {
        if (key === "default" || key === "__esModule" || dest.hasOwnProperty(key)) return;
        Object.defineProperty(dest, key, {
            enumerable: true,
            get: function() {
                return source[key];
            }
        });
    });
    return dest;
};
exports.export = function(dest, destName, get) {
    Object.defineProperty(dest, destName, {
        enumerable: true,
        get: get
    });
};

},{}]},["3D4o7","kYW5p"], "kYW5p", "parcelRequire16a5")

//# sourceMappingURL=index.5540d938.js.map
