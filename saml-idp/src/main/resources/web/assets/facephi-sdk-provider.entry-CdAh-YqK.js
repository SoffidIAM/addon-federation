import{r as ne,c as v,h as u,F as ie,g as re}from"./index-WKQCmRab.js";import{v as d,E as R,w as se,R as h,A as oe,a as F}from"./workflow.store-9e1c63a0-Dza5nofV.js";import{s as l,W as I,L as p,T,d as ae,o as j,e as le,E as g,f as E,g as ce,h as de}from"./store-de9de413-BW0vPw1M.js";import{u as Z}from"./browser-6b4c8cad-DKsL9QIc.js";import{a as he,i as N}from"./translations-6568027e-BSr74IOh.js";import"./_commonjsHelpers-1789f0cf-Cpj98o6Y.js";var P=function(n,t){return P=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,i){e.__proto__=i}||function(e,i){for(var r in i)Object.prototype.hasOwnProperty.call(i,r)&&(e[r]=i[r])},P(n,t)};function w(n,t){if(typeof t!="function"&&t!==null)throw new TypeError("Class extends value "+String(t)+" is not a constructor or null");P(n,t);function e(){this.constructor=n}n.prototype=t===null?Object.create(t):(e.prototype=t.prototype,new e)}function Y(n){var t=typeof Symbol=="function"&&Symbol.iterator,e=t&&n[t],i=0;if(e)return e.call(n);if(n&&typeof n.length=="number")return{next:function(){return n&&i>=n.length&&(n=void 0),{value:n&&n[i++],done:!n}}};throw new TypeError(t?"Object is not iterable.":"Symbol.iterator is not defined.")}function U(n,t){var e=typeof Symbol=="function"&&n[Symbol.iterator];if(!e)return n;var i=e.call(n),r,s=[],o;try{for(;(t===void 0||t-- >0)&&!(r=i.next()).done;)s.push(r.value)}catch(a){o={error:a}}finally{try{r&&!r.done&&(e=i.return)&&e.call(i)}finally{if(o)throw o.error}}return s}function X(n,t,e){if(e||arguments.length===2)for(var i=0,r=t.length,s;i<r;i++)(s||!(i in t))&&(s||(s=Array.prototype.slice.call(t,0,i)),s[i]=t[i]);return n.concat(s||Array.prototype.slice.call(t))}function m(n){return typeof n=="function"}function Q(n){var t=function(i){Error.call(i),i.stack=new Error().stack},e=n(t);return e.prototype=Object.create(Error.prototype),e.prototype.constructor=e,e}var G=Q(function(n){return function(e){n(this),this.message=e?e.length+` errors occurred during unsubscription:
`+e.map(function(i,r){return r+1+") "+i.toString()}).join(`
  `):"",this.name="UnsubscriptionError",this.errors=e}});function K(n,t){if(n){var e=n.indexOf(t);0<=e&&n.splice(e,1)}}var W=function(){function n(t){this.initialTeardown=t,this.closed=!1,this._parentage=null,this._finalizers=null}return n.prototype.unsubscribe=function(){var t,e,i,r,s;if(!this.closed){this.closed=!0;var o=this._parentage;if(o)if(this._parentage=null,Array.isArray(o))try{for(var a=Y(o),c=a.next();!c.done;c=a.next()){var b=c.value;b.remove(this)}}catch(f){t={error:f}}finally{try{c&&!c.done&&(e=a.return)&&e.call(a)}finally{if(t)throw t.error}}else o.remove(this);var k=this.initialTeardown;if(m(k))try{k()}catch(f){s=f instanceof G?f.errors:[f]}var D=this._finalizers;if(D){this._finalizers=null;try{for(var S=Y(D),y=S.next();!y.done;y=S.next()){var te=y.value;try{J(te)}catch(f){s=s??[],f instanceof G?s=X(X([],U(s)),U(f.errors)):s.push(f)}}}catch(f){i={error:f}}finally{try{y&&!y.done&&(r=S.return)&&r.call(S)}finally{if(i)throw i.error}}}if(s)throw new G(s)}},n.prototype.add=function(t){var e;if(t&&t!==this)if(this.closed)J(t);else{if(t instanceof n){if(t.closed||t._hasParent(this))return;t._addParent(this)}(this._finalizers=(e=this._finalizers)!==null&&e!==void 0?e:[]).push(t)}},n.prototype._hasParent=function(t){var e=this._parentage;return e===t||Array.isArray(e)&&e.includes(t)},n.prototype._addParent=function(t){var e=this._parentage;this._parentage=Array.isArray(e)?(e.push(t),e):e?[e,t]:t},n.prototype._removeParent=function(t){var e=this._parentage;e===t?this._parentage=null:Array.isArray(e)&&K(e,t)},n.prototype.remove=function(t){var e=this._finalizers;e&&K(e,t),t instanceof n&&t._removeParent(this)},n.EMPTY=function(){var t=new n;return t.closed=!0,t}(),n}(),q=W.EMPTY;function M(n){return n instanceof W||n&&"closed"in n&&m(n.remove)&&m(n.add)&&m(n.unsubscribe)}function J(n){m(n)?n():n.unsubscribe()}var pe={Promise:void 0},ue={setTimeout:function(n,t){for(var e=[],i=2;i<arguments.length;i++)e[i-2]=arguments[i];return setTimeout.apply(void 0,X([n,t],U(e)))},clearTimeout:function(n){return clearTimeout(n)},delegate:void 0};function fe(n){ue.setTimeout(function(){throw n})}function L(){}function x(n){n()}var $=function(n){w(t,n);function t(e){var i=n.call(this)||this;return i.isStopped=!1,e?(i.destination=e,M(e)&&e.add(i)):i.destination=be,i}return t.create=function(e,i,r){return new _(e,i,r)},t.prototype.next=function(e){this.isStopped||this._next(e)},t.prototype.error=function(e){this.isStopped||(this.isStopped=!0,this._error(e))},t.prototype.complete=function(){this.isStopped||(this.isStopped=!0,this._complete())},t.prototype.unsubscribe=function(){this.closed||(this.isStopped=!0,n.prototype.unsubscribe.call(this),this.destination=null)},t.prototype._next=function(e){this.destination.next(e)},t.prototype._error=function(e){try{this.destination.error(e)}finally{this.unsubscribe()}},t.prototype._complete=function(){try{this.destination.complete()}finally{this.unsubscribe()}},t}(W),me=function(){function n(t){this.partialObserver=t}return n.prototype.next=function(t){var e=this.partialObserver;if(e.next)try{e.next(t)}catch(i){C(i)}},n.prototype.error=function(t){var e=this.partialObserver;if(e.error)try{e.error(t)}catch(i){C(i)}else C(t)},n.prototype.complete=function(){var t=this.partialObserver;if(t.complete)try{t.complete()}catch(e){C(e)}},n}(),_=function(n){w(t,n);function t(e,i,r){var s=n.call(this)||this,o;return m(e)||!e?o={next:e??void 0,error:i??void 0,complete:r??void 0}:o=e,s.destination=new me(o),s}return t}($);function C(n){fe(n)}function ge(n){throw n}var be={closed:!0,next:L,error:ge,complete:L},ve=function(){return typeof Symbol=="function"&&Symbol.observable||"@@observable"}();function ye(n){return n}function Ie(n){return n.length===0?ye:n.length===1?n[0]:function(e){return n.reduce(function(i,r){return r(i)},e)}}var A=function(){function n(t){t&&(this._subscribe=t)}return n.prototype.lift=function(t){var e=new n;return e.source=this,e.operator=t,e},n.prototype.subscribe=function(t,e,i){var r=this,s=ke(t)?t:new _(t,e,i);return x(function(){var o=r,a=o.operator,c=o.source;s.add(a?a.call(s,c):c?r._subscribe(s):r._trySubscribe(s))}),s},n.prototype._trySubscribe=function(t){try{return this._subscribe(t)}catch(e){t.error(e)}},n.prototype.forEach=function(t,e){var i=this;return e=O(e),new e(function(r,s){var o=new _({next:function(a){try{t(a)}catch(c){s(c),o.unsubscribe()}},error:s,complete:r});i.subscribe(o)})},n.prototype._subscribe=function(t){var e;return(e=this.source)===null||e===void 0?void 0:e.subscribe(t)},n.prototype[ve]=function(){return this},n.prototype.pipe=function(){for(var t=[],e=0;e<arguments.length;e++)t[e]=arguments[e];return Ie(t)(this)},n.prototype.toPromise=function(t){var e=this;return t=O(t),new t(function(i,r){var s;e.subscribe(function(o){return s=o},function(o){return r(o)},function(){return i(s)})})},n.create=function(t){return new n(t)},n}();function O(n){var t;return(t=n??pe.Promise)!==null&&t!==void 0?t:Promise}function we(n){return n&&m(n.next)&&m(n.error)&&m(n.complete)}function ke(n){return n&&n instanceof $||we(n)&&M(n)}var Se=Q(function(n){return function(){n(this),this.name="ObjectUnsubscribedError",this.message="object unsubscribed"}}),ee=function(n){w(t,n);function t(){var e=n.call(this)||this;return e.closed=!1,e.currentObservers=null,e.observers=[],e.isStopped=!1,e.hasError=!1,e.thrownError=null,e}return t.prototype.lift=function(e){var i=new z(this,this);return i.operator=e,i},t.prototype._throwIfClosed=function(){if(this.closed)throw new Se},t.prototype.next=function(e){var i=this;x(function(){var r,s;if(i._throwIfClosed(),!i.isStopped){i.currentObservers||(i.currentObservers=Array.from(i.observers));try{for(var o=Y(i.currentObservers),a=o.next();!a.done;a=o.next()){var c=a.value;c.next(e)}}catch(b){r={error:b}}finally{try{a&&!a.done&&(s=o.return)&&s.call(o)}finally{if(r)throw r.error}}}})},t.prototype.error=function(e){var i=this;x(function(){if(i._throwIfClosed(),!i.isStopped){i.hasError=i.isStopped=!0,i.thrownError=e;for(var r=i.observers;r.length;)r.shift().error(e)}})},t.prototype.complete=function(){var e=this;x(function(){if(e._throwIfClosed(),!e.isStopped){e.isStopped=!0;for(var i=e.observers;i.length;)i.shift().complete()}})},t.prototype.unsubscribe=function(){this.isStopped=this.closed=!0,this.observers=this.currentObservers=null},Object.defineProperty(t.prototype,"observed",{get:function(){var e;return((e=this.observers)===null||e===void 0?void 0:e.length)>0},enumerable:!1,configurable:!0}),t.prototype._trySubscribe=function(e){return this._throwIfClosed(),n.prototype._trySubscribe.call(this,e)},t.prototype._subscribe=function(e){return this._throwIfClosed(),this._checkFinalizedStatuses(e),this._innerSubscribe(e)},t.prototype._innerSubscribe=function(e){var i=this,r=this,s=r.hasError,o=r.isStopped,a=r.observers;return s||o?q:(this.currentObservers=null,a.push(e),new W(function(){i.currentObservers=null,K(a,e)}))},t.prototype._checkFinalizedStatuses=function(e){var i=this,r=i.hasError,s=i.thrownError,o=i.isStopped;r?e.error(s):o&&e.complete()},t.prototype.asObservable=function(){var e=new A;return e.source=this,e},t.create=function(e,i){return new z(e,i)},t}(A),z=function(n){w(t,n);function t(e,i){var r=n.call(this)||this;return r.destination=e,r.source=i,r}return t.prototype.next=function(e){var i,r;(r=(i=this.destination)===null||i===void 0?void 0:i.next)===null||r===void 0||r.call(i,e)},t.prototype.error=function(e){var i,r;(r=(i=this.destination)===null||i===void 0?void 0:i.error)===null||r===void 0||r.call(i,e)},t.prototype.complete=function(){var e,i;(i=(e=this.destination)===null||e===void 0?void 0:e.complete)===null||i===void 0||i.call(e)},t.prototype._subscribe=function(e){var i,r;return(r=(i=this.source)===null||i===void 0?void 0:i.subscribe(e))!==null&&r!==void 0?r:q},t}(ee),V=function(n){w(t,n);function t(e){var i=n.call(this)||this;return i._value=e,i}return Object.defineProperty(t.prototype,"value",{get:function(){return this.getValue()},enumerable:!1,configurable:!0}),t.prototype._subscribe=function(e){var i=n.prototype._subscribe.call(this,e);return!i.closed&&e.next(this._value),i},t.prototype.getValue=function(){var e=this,i=e.hasError,r=e.thrownError,s=e._value;if(i)throw r;return this._throwIfClosed(),s},t.prototype.next=function(e){n.prototype.next.call(this,this._value=e)},t}(ee);class B{constructor(t){this.getDefaultData=()=>({version:this.apiKey?2:1,tenantId:this.tenantId,sessionId:this.sessionId,source:this.clientId,family:this.type}),this.generateOperationId=()=>new Promise(e=>{const i=d();this.operationId=i,e(i)}),this.generateStepId=()=>d(),this.trackingAsset=async(e,i,r,s,o)=>new Promise(async a=>{const c=new Date().getTime(),b=await this.apiService.requestUpload(this.trackingUrlAssets,e,{family:this.type,tenantId:this.tenantId,operationId:o||this.operationId,type:i}),k=new Date().getTime();await this.apiService.request(this.trackingUrl,{method:h.post,data:Object.assign(Object.assign({operationId:o||this.operationId},this.getDefaultData()),{events:[{eventId:d(),clientTimestamp:new Date().getTime(),executionTime:k-c,payload:{stepId:r,stepType:s,type:g.asset,source:this.getDefaultData().source,assetType:i,url:b.path,hash:b.hash,contentType:b.contentType}}]})}),a(!0)}),this.trackingSignature=async(e,i)=>{await this.apiService.request(this.trackingUrl,{method:h.post,data:Object.assign(Object.assign({operationId:i||this.operationId},this.getDefaultData()),{events:[{eventId:d(),clientTimestamp:new Date().getTime(),payload:{type:E.signature,timestamp:new Date().getTime(),result:e}}]})})},this.trackingStatus=(e,i,r,s,o)=>{this.apiService.request(this.trackingUrl,{method:h.post,data:Object.assign(Object.assign({},this.getDefaultData()),{operationId:o||this.operationId,events:[{eventId:d(),clientTimestamp:new Date().getTime(),payload:{stepId:r,stepType:s,type:E.result,status:e,reason:i}}]})})},this.trackingEvent=(e,i,r)=>this.apiService.request(this.trackingUrl,{method:h.post,data:Object.assign(Object.assign({operationId:r||this.operationId},this.getDefaultData()),{events:[{eventId:d(),clientTimestamp:new Date().getTime(),payload:{stepId:e,stepType:i,type:g.stepChange,widget:null,component:null}}]})}),this.trackingStepSuccess=(e,i,r)=>{this.apiService.request(this.trackingUrl,{method:h.post,data:Object.assign(Object.assign({operationId:r||this.operationId},this.getDefaultData()),{events:[{eventId:d(),clientTimestamp:new Date().getTime(),payload:{stepId:e,stepType:i,type:g.stepResult,status:ce.succeeded,reason:null}}]})})},this.trackingTerms=e=>{this.apiService.request(this.trackingUrl,{method:h.post,data:Object.assign(Object.assign({operationId:e||this.operationId},this.getDefaultData()),{events:[{eventId:d(),clientTimestamp:new Date().getTime(),payload:{type:g.termsConditions,timestamp:new Date().getTime(),accepted:!0}}]})})},this.trackingCustomerId=(e,i)=>{this.apiService.request(this.trackingUrl,{method:h.post,data:Object.assign(Object.assign({operationId:i||this.operationId},this.getDefaultData()),{events:[{eventId:d(),clientTimestamp:new Date().getTime(),payload:{type:this.type,screen:null,event:g.setCustomerId,value:e}}]})})},this.authenticate=async()=>{if(this.apiKey)return null;const e=await this.apiService.requestToken(this.clientId,this.clientSecret);return this.apiService.setToken(e),e},this.trackingStart=async(e,i)=>{const r=this.operationId||await this.generateOperationId(),s=[];return s.push({eventId:d(),clientTimestamp:new Date().getTime(),payload:{stepId:this.generateStepId(),stepType:de.start,type:g.stepChange,component:null,widget:null}}),s.push({eventId:d(),clientTimestamp:new Date().getTime(),executionTime:null,payload:{type:E.device,deviceType:this.deviceType,osVersion:this.browser.version,model:this.browser.version,brand:this.browser.name,browser:this.browser.name,osName:this.os.name}}),e&&s.push({eventId:d(),clientTimestamp:new Date().getTime(),executionTime:null,payload:{type:g.stepFlows,id:null,steps:e,reducedId:null,reducedSteps:null}}),i&&s.push({eventId:d(),clientTimestamp:new Date().getTime(),executionTime:null,payload:{type:this.type,screen:null,event:g.setCustomerId,value:i||this.customerId}}),await this.apiService.request(this.trackingUrl,{method:h.post,data:Object.assign(Object.assign({operationId:this.operationId},this.getDefaultData()),{events:s})}),{operationId:r,sessionId:this.sessionId}},this.apiService=new oe({authUrl:t.authUrl,apiKey:t.apiKey}),this.trackingUrlAssets=t.trackingUrlAssets,this.type=t.type,this.tenantId=t.tenantId,this.trackingUrl=t.trackingUrl,this.sessionId=d(),this.clientId=t.clientId?t.clientId:t.landing?"landing":d(),this.clientSecret=t.clientSecret,this.apiKey=t.apiKey,this.apiKey=t.apiKey,this.browser=Z().browser,this.os=Z().os,this.deviceType=Z().deviceType,this.customerId=t.customerId,this.operationId=t.operationId}}class Ce{constructor(){this.myData=new V(""),this.statusLicense=new V(""),this.myLicense=new V(null),this.loaded=!1,this.init=(t,e)=>{if(t&&(l.resourcesPath=t),!this.loaded&&!this.innerWorker){const i="LyogZXNsaW50LWRpc2FibGUgbm8tdW5kZWYgKi8KbGV0IG1vZHVsZTsKbGV0IGRvd25sb2FkQnVmZlRva2VuaXplcjsKbGV0IG1vZHVsZUxpY2Vuc2U7CmxldCBkb3dubG9hZEJ1ZmZMaWNlbnNlOwpsZXQgd2FzbUluc3RhbmNlVG9rZW5pemVyOwpsZXQgd2FzbUluc3RhbmNlTGljZW5zZTsKbGV0IGluc3RhbmNlTGljZW5zZTsKbGV0IGluc3RhbmNlVG9rZW5pemVyOwpsZXQgdG9rZW5pemVyRGF0YTsKCmNvbnN0IGluaXRpYWxpemVXb3JrZXIgPSBhc3luYyAodG9rZW5pemVyTG9jYXRpb25VcmwsIGxpY2Vuc2VMb2NhdGlvblVybCkgPT4gewoJbW9kdWxlID0gYXdhaXQgaW1wb3J0KGAke3Rva2VuaXplckxvY2F0aW9uVXJsfS9SdW50aW1lLmpzYCk7Cglkb3dubG9hZEJ1ZmZUb2tlbml6ZXIgPSBhd2FpdCBmZXRjaChgJHt0b2tlbml6ZXJMb2NhdGlvblVybH0vRkJUb2tlbml6ZXIud2FzbWApOwoJbW9kdWxlTGljZW5zZSA9IGF3YWl0IGltcG9ydChgJHtsaWNlbnNlTG9jYXRpb25Vcmx9L0ZCbGljZW5zaW5nTGl0ZS5qc2ApOwoJZG93bmxvYWRCdWZmTGljZW5zZSA9IGF3YWl0IGZldGNoKGAke2xpY2Vuc2VMb2NhdGlvblVybH0vRkJsaWNlbnNpbmdMaXRlLndhc21gKTsKCgl3YXNtSW5zdGFuY2VUb2tlbml6ZXIgPSBhd2FpdCBkb3dubG9hZEJ1ZmZUb2tlbml6ZXIuYXJyYXlCdWZmZXIoKTsKCXdhc21JbnN0YW5jZUxpY2Vuc2UgPSBhd2FpdCBkb3dubG9hZEJ1ZmZMaWNlbnNlLmFycmF5QnVmZmVyKCk7CgoJaW5zdGFuY2VMaWNlbnNlID0gYXdhaXQgbW9kdWxlTGljZW5zZS5kZWZhdWx0KHsKCQl3YXNtQmluYXJ5OiB3YXNtSW5zdGFuY2VMaWNlbnNlLAoJCW9uUnVudGltZUluaXRpYWxpemVkOiAoKSA9PiBzZWxmLnBvc3RNZXNzYWdlKHsgbWVzc2FnZTogJ2luaXRpYWxpemVkJywgZGF0YTogbnVsbCB9KSwKCX0pOwoKCWluc3RhbmNlVG9rZW5pemVyID0gYXdhaXQgbW9kdWxlLmRlZmF1bHQoewoJCXdhc21CaW5hcnk6IHdhc21JbnN0YW5jZVRva2VuaXplciwKCQlvblJ1bnRpbWVJbml0aWFsaXplZDogKCkgPT4gc2VsZi5wb3N0TWVzc2FnZSh7IG1lc3NhZ2U6ICdpbml0aWFsaXplZCcsIGRhdGE6IG51bGwgfSksCgl9KTsKCgl0b2tlbml6ZXJEYXRhID0gbmV3IGluc3RhbmNlVG9rZW5pemVyLlRva2VuaXplckRhdGEoKTsKfTsKCnNlbGYub25tZXNzYWdlID0gYXN5bmMgZnVuY3Rpb24gKGUpIHsKCXN3aXRjaCAoZS5kYXRhLm1lc3NhZ2UpIHsKCQljYXNlICdpbml0JzoKCQkJYXdhaXQgaW5pdGlhbGl6ZVdvcmtlcihlLmRhdGEudG9rZW5pemVyTG9jYXRpb25VcmwsIGUuZGF0YS5saWNlbnNlTG9jYXRpb25VcmwpOwoJCQlicmVhazsKCQljYXNlICdleHRyYURhdGEnOgoJCQlzZW5kRXh0cmFEYXRhKGUuZGF0YS5kYXRhKTsKCQkJYnJlYWs7CgkJY2FzZSAndmFsaWRMaWNlbnNlJzogewoJCQlpc1ZhbGlkTGljZW5zZShKU09OLnN0cmluZ2lmeShlLmRhdGEuZGF0YSkpOwoJCQlicmVhazsKCQl9CgkJY2FzZSAnZ2V0RW5hYmxlZENvbXBvbmVudHMnOiB7CgkJCWxldCByZXN1bHRzID0ge307CgkJCWNvbnN0IGNvbXBvbmVudHMgPSBlLmRhdGEuY29tcG9uZW50c05hbWU7CgkJCWNvbXBvbmVudHMubWFwKGl0ZW0gPT4gewoJCQkJY29uc3QgbmV3Q29tcG9uZW50ID0gZ2V0RW5hYmxlZENvbXBvbmVudHMoSlNPTi5zdHJpbmdpZnkoZS5kYXRhLmxpY2Vuc2UpLCBpdGVtKTsKCQkJCWlmIChuZXdDb21wb25lbnQpIHsKCQkJCQlyZXN1bHRzID0geyAuLi5yZXN1bHRzLCBbaXRlbV06IG5ld0NvbXBvbmVudCB9OwoJCQkJfQoJCQl9KTsKCQkJc2VsZi5wb3N0TWVzc2FnZSh7IG1lc3NhZ2U6ICdnZXRFbmFibGVkQ29tcG9uZW50cycsIGRhdGE6IHJlc3VsdHMgfSk7CgkJfQoJfQp9OwoKY29uc3QgaXNWYWxpZExpY2Vuc2UgPSBsaWNlbnNlID0+IHsKCXRyeSB7CgkJY29uc3QgcmVzdWx0ID0gaW5zdGFuY2VMaWNlbnNlLmlzVmFsaWRMaWNlbnNlKGxpY2Vuc2UpOwoJCWNvbnN0IGxpY2Vuc2VTdGF0dXMgPSBpbnN0YW5jZUxpY2Vuc2UuTGljZW5zZVN0YXR1cy52YWx1ZXNbcmVzdWx0LnZhbHVlXTsKCgkJc2VsZi5wb3N0TWVzc2FnZSh7CgkJCW1lc3NhZ2U6ICdpc1ZhbGlkTGljZW5zZScsCgkJCWRhdGE6IGxpY2Vuc2VTdGF0dXMuY29uc3RydWN0b3IubmFtZSwKCQl9KTsKCX0gY2F0Y2ggKGVycm9yKSB7CgkJc2VsZi5wb3N0TWVzc2FnZSh7CgkJCW1lc3NhZ2U6ICdpbnZhbGlkTGljZW5zZScsCgkJfSk7Cgl9Cn07Cgpjb25zdCBzZW5kRXh0cmFEYXRhID0gZGF0YSA9PiB7CgkvLyBDcmVhdGUgZXh0cmEgZGF0YQoJY29uc3Qga2V5ID0gJ0V4dHJhRGF0YSc7Cgljb25zdCB2YWx1ZSA9IEpTT04uc3RyaW5naWZ5KGRhdGEpOwoJdG9rZW5pemVyRGF0YS5hZGRFeHRyYURhdGEoa2V5LCB2YWx1ZSwgbnVsbCk7CgoJLy8gV3JpdGUgYW5kIGVuY3J5cHQgZXh0cmEgZGF0YSBpbiB0aGUgdG9rZW5pemVyRGF0YSBpbnN0YW5jZS4KCWNvbnN0IGJ1ZmZlciA9IHRva2VuaXplckRhdGEud3JpdGUobnVsbCk7Cgljb25zdCBlbmNyeXB0ZWQgPSBpbnN0YW5jZVRva2VuaXplci5FbmNyeXB0QmFzZTY0KGJ1ZmZlciwgbnVsbCk7CgoJLy8gU2VuZCB0aGUgZW5jcnlwdGVkIGRhdGEuCglzZWxmLnBvc3RNZXNzYWdlKHsgbWVzc2FnZTogJ2VuY3J5cHRlZERhdGEnLCBkYXRhOiBlbmNyeXB0ZWQgfSk7Cn07Cgpjb25zdCBnZXRFbmFibGVkQ29tcG9uZW50cyA9IChsaWNlbnNlLCBjb21wb25lbnROYW1lKSA9PiB7Cgljb25zdCByZXN1bHRzID0gaW5zdGFuY2VMaWNlbnNlLmdldEVuYWJsZWRDb21wb25lbnRzKGxpY2Vuc2UsIGNvbXBvbmVudE5hbWUpOwoKCWNvbnN0IGNvbXBvbmVudHNWZWMgPSByZXN1bHRzLmdldENvbXBvbmVudHMoKTsKCWxldCBvYmplY3RDb21wb25lbnQ7CgoJZm9yIChsZXQgaSA9IDA7IGkgPCBjb21wb25lbnRzVmVjLnNpemUoKTsgaSsrKSB7CgkJY29uc3QgY29tcG9uZW50ID0gY29tcG9uZW50c1ZlYy5nZXQoaSk7CgoJCW9iamVjdENvbXBvbmVudCA9IHsKCQkJcGFyYW1ldGVyczogY29tcG9uZW50LmxpY2Vuc2UgIT09ICcnID8gSlNPTi5wYXJzZShjb21wb25lbnQubGljZW5zZSkgOiBudWxsLAoJCX07Cgl9CgoJcmV0dXJuIG9iamVjdENvbXBvbmVudDsKfTsK",r=new Blob([atob(i)],{type:"application/javascript"}),s=URL.createObjectURL(r),o=()=>new Worker(s,{type:"module"});this.innerWorker=o(),this.innerWorker.onmessage=a=>{switch(a.data.message){case"initialized":this.loaded=!0,e&&e();break;case"encryptedData":this.myData.next(a.data.data);break}},this.innerWorker.postMessage({message:"init",tokenizerLocationUrl:`${t||F}/tokenizer/0.1.0`,licenseLocationUrl:`${t||F}/sdk/0.1.0/licensingLite`})}}}async validLicense(t){return new Promise((e,i)=>{this.innerWorker.postMessage({message:"validLicense",data:t}),this.innerWorker.onmessage=r=>{switch(r.data.message){case"invalidLicense":{console.error("The license is invalid, please contact Facephi for more information"),i("invalid license");break}case"isValidLicense":{e(r.data.data);break}}}})}getEnabledComponents(t){return new Promise(e=>{this.innerWorker.postMessage({message:"getEnabledComponents",license:t,componentsName:[p.tracking,p.selphiWidget,p.selphidWidget,p.videoRecording,p.videoRecruitment,p.flow,p.voiceRecording,p.landing,p.videoAssistance,p.test]}),this.innerWorker.onmessage=i=>{switch(i.data.message){case"getEnabledComponents":{e(i.data.data);break}}}})}async generateExtraData({customerId:t,operationId:e,trackingFamily:i,trackingOptions:r,sessionId:s}){return new Promise((o,a)=>{try{if(t&&e&&i&&s&&r&&this.innerWorker){const c=new URL(r==null?void 0:r.authUrl);this.innerWorker.postMessage({message:"extraData",data:{customerId:t,operationId:e,FACEPHI_SELPHID_TRACKING_TENANT_UUID:r==null?void 0:r.tenantId,FACEPHI_SELPHID_TRACKING_USER_KEY:r==null?void 0:r.clientId,FACEPHI_SELPHID_TRACKING_URL_KEY:c.origin,FACEPHI_SELPHID_TRACKING_PASSWORD_KEY:r==null?void 0:r.clientSecret,sessionId:s,family:i,FACEPHI_SELPHID_TRACKING_ASSETS_ENDPOINT:"/api/assets/",FACEPHI_SELPHID_TRACKING_EVENTS_ENDPOINT:"/api/tracking/events",FACEPHI_SELPHID_TRACKING_AUTH_ENDPOINT:"/auth/realms/inphinite/protocol/openid-connect/token",FACEPHI_SELPHID_TRACKING_EVENT_SOURCE:"backend.sdk"}})}this.innerWorker.onmessage=c=>{switch(c.data.message){case"encryptedData":{o(c.data.data);break}}}}catch(c){a(c)}})}}class xe{getLicense(t){return fetch(l.dev?"https://license.identity-platform.dev":"https://license.identity-platform.io",{mode:"cors",method:"GET",headers:{"x-api-key":t,"Content-Type":"application/json"}}).then(async e=>{const i=await e.json();if(i.statusCode===401)throw new Error(i.message);if(new Date(i.dateEnd).getTime()<new Date().getTime())throw new Error(R.LICENSE_EXPIRED);return i}).catch(e=>{throw new Error(e.message==="Failed to fetch"?R.LICENSE_SERVICE_ERROR:e.message)})}checkOrigin(t){return fetch(l.dev?"https://license.identity-platform.dev":"https://license.identity-platform.io/check-origin",{mode:"cors",method:"GET",headers:{"x-api-key":t,"Content-Type":"application/json"}}).then(async e=>await e.json())}}class We{constructor(t){this.request=(e,i)=>new Promise((r,s)=>fetch(`${this.apiUrl}${e}`,{method:i.method,mode:"cors",headers:Object.assign({"content-type":"application/json"},i.headers),body:JSON.stringify(i.data)}).then(o=>{if(o.ok)r(o.json());else throw new Error("Something went wrong")}).catch(o=>{s(o)})),this.apiUrl=t.apiUrl,this.source=t.source,this.apiKey=t.apiKey,this.operationId=t.operationId,this.generateSessionId()}async start(t){try{return await this.request("/conductor/workflows/start",{method:h.post,data:t,headers:{"x-api-key":this.apiKey,"x-source":this.source}})}catch(e){throw new Error(e)}}async session(t){return await this.request(`/conductor/operations/${this.operationId}/session`,{method:h.post,data:t})}generateSessionId(){this.sessionId=d()}async event(t,e,i){return await this.request(`/conductor/operations/${i}/events`,{method:h.post,data:{stepId:t,events:e}})}}class Te{constructor(t){this.request=(e,i)=>fetch(`${this.apiUrl}${e}`,{method:i.method,mode:"cors",body:JSON.stringify(i.data),headers:{"x-api-key":this.apiKey,"content-type":"application/json"}}).then(async r=>{if(r.ok){const s=r.headers.get("content-type");return s&&s.includes("application/json")?r.json():null}else{const s=await r.text();throw new Error(`HTTP Error ${r.status}: ${s}`)}}).catch(r=>{throw console.log(r),new Error(r)}),this.sendReniec=(e,i,r)=>this.request("/identiphi/PER",{method:h.post,data:Object.assign(Object.assign({},e),{operationId:i,sessionId:r})}),this.sendSelphid=({front:e,back:i,country:r},s,o)=>this.request("/selphid",{method:h.post,data:{front:e,back:i,country:r,operationId:s,sessionId:o,tenantId:this.tenantId}}),this.sendVideoContracting=(e,i)=>this.request("/videocontracting",{method:h.post,data:{operationId:e,sessionId:i,tenantId:this.tenantId}}),this.sendSelphi=(e,i,r)=>this.request("/selphi",{method:h.post,data:{image:e.replace("data:image/jpeg;base64,",""),operationId:i,sessionId:r,tenantId:this.tenantId}}),this.getResults=e=>new Promise((i,r)=>{this.request(`/result/${e}`,{method:h.get}).then(s=>{s.error&&r(s),i(s)})}),this.apiKey=t.apiKey,this.apiUrl=t.apiUrl,this.tenantId=t.tenantId}}const H=({text:n,show:t=!1})=>t?u("div",{class:"loading"},u("div",{class:"lds-ellipsis"},u("div",null),u("div",null),u("div",null),u("div",null)),n&&N.t(n,{missingBehavior:"empty"})&&u("p",null,N.t(n,{missingBehavior:"empty"}))):null,Ee=`:host {
  --secondaryColor: #3167FC
}

* {
  box-sizing: border-box;
}

h1,
h2,
h3,
h4,
h5,
h6 {
  font-weight: 400;
}

h1,
h2,
h3,
h4,
h5,
h6,
p,
ul,
li {
  margin: 0;
  padding: 0;
}

/* Form */

.form {
  height: 100%;
  width: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;

  @media (max-width: 767px) {
    max-width: 100%;
    justify-content: space-between;
  }
}

.form-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  overflow-y: auto;
  padding: var(--padding) var(--padding) 0;

  @media (max-width: 767px) {
    margin: auto 0;
  }
}

.tip-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  padding: var(--padding) var(--padding) 0;
  margin: 0 auto;

  @media (max-width: 767px) {
    margin: auto 0;
  }
}

.form-submit {
  padding: var(--padding) 0;
  width: var(--maxWidthField);
  @media (max-width: 767px) {
    padding: var(--padding);
    width: 100%;
  }
}

.form-submit .button {
  @media (max-width: 767px) {
    max-width: 100%;
  }
}

/* Button */
.button {
  height: 48px;
  padding: 0px 10px;
  border-radius: 8px;
  border: 0px;
  color: var(--whiteColor);
  background: var(--secondaryColor);
  width: 100%;
  max-width: var(--maxWidthField);
  font-family: inherit;
  font-weight: 600;
  font-size: 16px;
  line-height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto;
}

.button--small {
  height: 40px;
  font-size: 14px;
  line-height: 21px;
}

.button:disabled {
  background-color: var(--backgroundDisabled);
  color: var(--fontColorDisabled);
}

.button:hover:not(:disabled) {
  cursor: pointer;
  background: var(--tertiaryColor);
}

.button--link {
  background: none;
  color: var(--secondaryColor);
}

.button--link:hover {
  background: none !important;
}

/* Card */

.card {
  background: white;
  border-radius: 24px;
  padding: 30px;
  box-shadow: 0px 2px 14px 0px #EAEEF6;
}


/* Fonts */

.fs-xl {
  font-size: 32px;
  line-height: 44px;
  font-family: inherit;
  color: var(--fontColor);

  @media (max-width: 767px) {
    font-size: 21px;
    line-height: 32px;
  }
}

.fs-l {
  font-size: 21px;
  line-height: 32px;
  font-family: inherit;
  color: var(--fontColor);

  @media (max-width: 767px) {
    font-size: 16px;
    line-height: 24px;
  }
}

.fs-m {
  font-size: 16px;
  line-height: 24px;
  font-family: inherit;
  color: var(--fontColor);

  @media (max-width: 767px) {
    font-size: 14px;
    line-height: 21px;
  }
}

.fs-sm {
  font-size: 14px;
  line-height: 21px;
  font-family: inherit;
  color: var(--fontColor);

  @media (max-width: 767px) {
    font-size: 14px;
    line-height: 21px;
  }
}

.fs-s {
  font-size: 12px;
  line-height: 16px;
  font-family: inherit;
  color: var(--fontColor);

  @media (max-width: 767px) {
    font-size: 12px;
    line-height: 16px;
  }
}

.fc-error {
  color: var(--errorColor) !important;
}

.fc-success {
  color: var(--successColor) !important;
}

.fc-white {
  color: var(--whiteColor) !important;
}

.fc-secondary {
  color: var(--fontSecondaryColor) !important;
}

.fw-600 {
  font-weight: 600;
}

.text-center {
  text-align: center;
}

.text-uppercase {
  text-transform: uppercase;
}

.label-input {
  font-size: 12px;
  line-height: 16px;
  font-family: inherit;
  color: var(--fontColor);
  font-weight: 600;
  margin-bottom: 4px;

  @media (max-width: 767px) {
    font-size: 12px;
    line-height: 16px;
  }
}

.label-error {
  font-size: 12px;
  line-height: 16px;
  font-family: inherit;
  color: var(--errorColor);
  margin-top: 4px;

  @media (max-width: 767px) {
    font-size: 12px;
    line-height: 16px;
  }
}

/* Spacing */

.mt-4 {
  margin-top: 4px;
}

.mb-4 {
  margin-bottom: 4px;
}
`,Ze=Ee,Ge=`:host {
  --borderColor: #ccd4e5;
  --whiteColor: #ffffff;
  --fontColor: #1d2c4d;
  --fontSecondaryColor: #526080;
  --errorColor: #dd3631;
  --successColor: #0f8837;
  --backgroundDisabled: #eaeef6;
  --fontColorDisabled: #afb8cc;
  --maxWidthField: 350px;
  --heightField: 40px;
  --rowGap: 24px;
  --padding: 48px;
  --hoverBackground: #f3f4f9;

  display: flex;
  flex: 1;
  flex-direction: column;
  width: 100%;
  height: 100%;

  /* Config Theme */
  --primaryColor: transparent;
  --secondaryColor: #7636fc;
  --tertiaryColor: #572bb6;
  --backgroundColor: transparent;

  @media (max-width: 767px) {
    --maxWidthField: 100%;
    --rowGap: 16px;
    --padding: 16px;
  }
}

:host > div {
  display: flex;
  flex: 1;
  flex-direction: column;
  width: 100%;
  height: 100%;
  position: relative;
}

.loading {
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  width: 100%;
  z-index: 1;
  display: flex;
  justify-content: center;
  align-items: center;
}

.loading p {
  padding-top: 200px;
  font-weight: bold;
  color: #243760;
}

.lds-ellipsis {
  width: 160px;
  height: 100px;
  display: inline-block;
  overflow: hidden;
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

.lds-ellipsis div {
  position: absolute;
  top: 33px;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: #243760;
  animation-timing-function: cubic-bezier(0, 1, 1, 0);
}

.lds-ellipsis div:nth-child(1) {
  left: 20px;
  animation: lds-ellipsis1 0.45s infinite;
}
.lds-ellipsis div:nth-child(2) {
  left: 20px;
  animation: lds-ellipsis2 0.45s infinite;
}
.lds-ellipsis div:nth-child(3) {
  left: calc(20px + 48px);
  animation: lds-ellipsis2 0.45s infinite;
}
.lds-ellipsis div:nth-child(4) {
  left: calc(20px + 48px + 48px);
  animation: lds-ellipsis3 0.45s infinite;
}
@keyframes lds-ellipsis1 {
  0% {
    transform: scale(0);
  }
  100% {
    transform: scale(1);
  }
}
@keyframes lds-ellipsis2 {
  0% {
    transform: translate(0, 0);
  }
  100% {
    transform: translate(48px, 0);
  }
}
@keyframes lds-ellipsis3 {
  0% {
    transform: scale(1);
  }
  100% {
    transform: scale(0);
  }
}
`,Ve=Ge,Re=class{watchOperationId(n){l.operationId=n}watchLoaded(n){n||this.workflowHandleEvent(I.loaded)}watchComponents(n){if(n){l.components=n;const t=n[p.tracking],e=n[p.flow],i=n[p.landing],r=n[p.test];if(this.getComponents(),r&&(l.test=!0),e&&!this.disabled){const s=e.parameters;this.flowService=new We({apiUrl:s.apiUrl,apiKey:s.apiKey,source:s.source,operationId:this.operationId}),this.operationId?this.initSesion():this.initFlow()}if(i){if(this.disabled)return this.licenseLoaded=!0,l.loading=!1,!1;this.landingParameters=i.parameters,this.widgetService=new Te({apiKey:this.landingApiKey,apiUrl:this.landingParameters.apiUrl,tenantId:this.tenantId}),l.tenantId=this.tenantId,this.trackingService=new B({authUrl:`${this.landingParameters.apiUrl}/auth/realms/inphinite/protocol/openid-connect/token`,apiKey:this.landingApiKey,trackingUrl:`${this.landingParameters.apiUrl}/trail/event`,trackingUrlAssets:`${this.landingParameters.apiUrl}/trail/asset`,tenantId:this.tenantId,customerId:this.customerId||d(),type:this.type||T.onboarding,bundlePath:this.bundlePath,operationId:this.operationId,landing:!0}),this.autoInitTracking?this.disabled||this.qr?l.loading=!1:this.initTracking():l.loading=!1}t&&!e&&(this.trackingParameters=t.parameters,l.tenantId=this.tenantId||this.trackingParameters.tenantId,this.trackingService=new B({authUrl:`${this.trackingParameters.apiUrl}/auth/realms/inphinite/protocol/openid-connect/token`,apiKey:this.trackingParameters.apiKey,clientId:this.trackingParameters.clientId,clientSecret:this.trackingParameters.clientSecret,trackingUrl:`${this.trackingParameters.apiUrl}/api/tracking/events`,trackingUrlAssets:`${this.trackingParameters.apiUrl}/api/assets/`,tenantId:this.tenantId||this.trackingParameters.tenantId,customerId:this.customerId||d(),type:this.type||T.onboarding,bundlePath:this.bundlePath,operationId:this.operationId}),this.autoInitTracking?this.disabled?l.loading=!1:this.initTracking():l.loading=!1),(!t&&!e&&!i||this.disabled)&&(this.operationId=this.operationId||d(),this.sessionId=d(),l.loading=!1,this.emitOperationId.emit(this.operationId),this.emitSessionId.emit(this.sessionId),this.emitData.emit({operationId:this.operationId,extraData:null,sessionId:this.sessionId})),i&&this.emitData.emit({operationId:this.operationId,extraData:null,sessionId:this.sessionId}),this.licenseLoaded=!0}}constructor(n){ne(this,n),this.emitExtraData=v(this,"emitExtraData"),this.emitOperationId=v(this,"emitOperationId"),this.emitSessionId=v(this,"emitSessionId"),this.emitData=v(this,"emitData"),this.emitError=v(this,"emitError"),this.emitWorkflowEvent=v(this,"emitWorkflowEvent"),this.desktopView=void 0,this.customerId=void 0,this.apikey=void 0,this.type=T.onboarding,this.steps=void 0,this.disabled=void 0,this.bundlePath=void 0,this.workflow=void 0,this.theme=void 0,this.language=ae.es,this.debug=!1,this.dev=!1,this.operationId=void 0,this.autoInitWorkflow=!0,this.autoInitTracking=!0,this.tenantId=void 0,this.qr=void 0,this.qrExtraParams=void 0,this.waitRequest=!1,this.landingApiKey=void 0,this.resourcesPath=void 0,this.loading=!0,this.licenseLoaded=!1,this.sessionId=void 0,this.components=void 0,this.error=void 0,this.trackingParameters=void 0,this.landingParameters=void 0,this.isLoadTracking=!1,this.trackingService=void 0,this.flowService=void 0,this.widgetService=void 0,this.apikey?this.securityService=new Ce:console.warn("ApiKey prop is required")}async initSesion(){const n=await this.flowService.session({customerId:this.customerId,sessionId:this.flowService.sessionId});this.workflow||(this.workflow=n.config.workflow.definition),this.theme||this.updateTheme(n.config.theme),this.isLoadTracking=!0,l.loading=!1}async initFlow(){try{const n=await this.flowService.start({customerId:this.customerId,sessionId:this.flowService.sessionId});this.operationId=n.operationId,this.isLoadTracking=!0,l.loading=!1}catch(n){this.emitError.emit({message:n,statusCode:500})}}async updateTheme(n){const t=["primaryColor","secondaryColor","tertiaryColor","backgroundColor"];for(const e of t)n[e]&&this.host.style.setProperty(`--${e}`,n[e]);if(n.fontName){const e=document.querySelector("link[data-theme-font]");e&&e.remove();const i=document.createElement("link");i.setAttribute("rel","stylesheet"),i.setAttribute("href",`https://fonts.googleapis.com/css2?family=${n.fontName}:wght@400;600&display=swap`),i.setAttribute("data-theme-font","true"),document.head.appendChild(i),this.host.style.fontFamily=n.fontName}}async haveTracking(){}async initExternalTracking(){if(this.disabled||this.flowService)return!0;for(;!this.trackingService;)await new Promise(n=>setTimeout(n,100));await this.initTracking()}async initTracking(){var n,t,e,i;try{if(!this.trackingService&&this.flowService)return!1;const r=this.components.landing;r||await this.trackingService.authenticate();const{operationId:s,sessionId:o}=await this.trackingService.trackingStart(this.steps,this.customerId);this.operationId=this.operationId||s,l.operationId=this.operationId||s,this.sessionId=o,this.isLoadTracking=!0,this.emitOperationId.emit(this.operationId),this.emitSessionId.emit(o),l.loading=!1,!r&&this.securityService.generateExtraData({customerId:this.customerId,operationId:s,sessionId:o,trackingFamily:this.type,trackingOptions:{tenantId:this.tenantId||((n=this.trackingParameters)===null||n===void 0?void 0:n.tenantId),clientId:(t=this.trackingParameters)===null||t===void 0?void 0:t.clientId,clientSecret:(e=this.trackingParameters)===null||e===void 0?void 0:e.clientSecret,authUrl:(i=this.trackingParameters)===null||i===void 0?void 0:i.apiUrl}}).then(a=>{this.emitExtraData.emit(a),this.emitData.emit({operationId:s,extraData:a,sessionId:o})})}catch(r){this.workflowHandleEvent(I.error,null,r)}}async componentWillLoad(){l.bundlePath=this.bundlePath,l.desktopView=this.desktopView,l.debug=this.debug,l.initWorkflow=this.autoInitWorkflow,l.dev=this.dev,l.wait=this.waitRequest,l.loading=!0,j("loading",t=>{this.loading=t}),j("operationId",t=>{t!==this.operationId&&(this.operationId=t,this.emitOperationId.emit(t))}),this.qr?l.initTracking=!1:l.initTracking=this.autoInitTracking,this.language&&(l.language=this.language,he(this.language)),this.theme&&this.updateTheme(this.theme),N.locale=this.language,this.licenseService=new xe;const n=await this.licenseService.getLicense(this.apikey).catch(t=>(this.error=t.message,!1));this.securityService.init(this.resourcesPath,async()=>{n&&await this.securityService.validLicense(n).catch(()=>{this.error=R.LICENSE_INVALID})===le.valid&&(this.components=await this.securityService.getEnabledComponents(n))})}checkTracking(){return new Promise(n=>{const t=setInterval(()=>{this.isLoadTracking&&(n(!0),clearInterval(t))},3)})}async workflowHandleEvent(n,t,e){this.emitWorkflowEvent.emit({type:n,stepId:t,data:e}),se.currentState={type:n,stepId:t}}async sendError(n){this.emitError.emit(n)}async loadTracking(){return this.disabled?!0:this.checkTracking()}async trackingEvent(n,t){this.trackingService&&this.trackingService.trackingEvent(n,t).catch(e=>{console.log("error",e)})}async flowEvent(n,t){return this.flowService?this.flowService.event(n,t,this.operationId):Promise.resolve(null)}async getComponents(){return this.components}async haveTrackingService(){return new Promise(n=>{const t=setInterval(()=>{this.widgetService&&(n(!0),clearInterval(t)),this.flowService&&(n(!0),clearInterval(t)),this.disabled&&(n(!1),clearInterval(t)),this.trackingService&&(n(!0),clearInterval(t))},3)})}async haveFlowService(){return!!this.flowService}async generateStepId(){return this.trackingService&&this.trackingService.generateStepId()}async trackingAsset(n,t,e,i){return this.trackingService?this.trackingService.trackingAsset(n,t,e,i):Promise.resolve(!0)}async trackingStatus(n,t,e,i){this.trackingService&&this.trackingService.trackingStatus(n,t,e,i)}async trackingStepSuccess(n,t){this.trackingService&&this.trackingService.trackingStepSuccess(n,t)}async trackingTerms(){this.trackingService&&this.trackingTerms()}async trackingSignature(n){this.trackingService&&this.operationId&&this.trackingService.trackingSignature(n,this.operationId)}async getOperationId(){return this.operationId}async callReniec(n){this.operationId&&this.sessionId&&this.widgetService&&this.widgetService.sendReniec(n,this.operationId,this.sessionId)}async sendSelphid(n){return this.operationId&&this.sessionId&&this.widgetService?this.widgetService.sendSelphid(n,this.operationId,this.sessionId):Promise.resolve(!0)}async sendSelphi(n){return this.operationId&&this.sessionId&&this.widgetService?this.widgetService.sendSelphi(n,this.operationId,this.sessionId):Promise.resolve(!0)}async sendVideoContracting(){this.operationId&&this.sessionId&&this.widgetService&&this.widgetService.sendVideoContracting(this.operationId,this.sessionId)}async callResults(){return this.operationId&&this.widgetService?this.widgetService.getResults(this.operationId):null}async getWorkflowConfiguration(){return{workflow:this.workflow,operationId:this.operationId,bundlePath:this.bundlePath,qr:this.qr}}render(){const n=u(ie,{key:"f125cab1289bdfe35bc63e9844ba82a75b143a2a"},u(H,{key:"d704b046bedc0e32bebd0776bd6bcabf483e8e23",text:l.loadingText,show:this.loading&&this.licenseLoaded}),u("facephi-workflow-provider",{key:"0ba5bc19ede53e1e5396397a5250876ae26d5193",workflow:this.workflow,bundlePath:this.bundlePath,onWorkflowStarted:t=>this.workflowHandleEvent(I.start,t.detail.stepId),onWorkflowFinished:t=>this.workflowHandleEvent(I.finish,t.detail.stepId),onWorkflowChangeStep:t=>this.workflowHandleEvent(I.changeStep,t.detail.stepId,t.detail.data),qr:this.qr,qrParameters:this.qrExtraParams,operationId:this.operationId,style:{display:this.loading?"none":"block"}}));return u("div",{key:"afbe0862ebf461e43aac7eeddb5cbfe9183c4943"},this.loading&&!this.licenseLoaded?u(H,{show:!0}):this.error?u("error-view",{text:this.error}):this.licenseLoaded&&this.workflow&&l.initWorkflow?n:u("slot",null))}get host(){return re(this)}static get watchers(){return{operationId:["watchOperationId"],loading:["watchLoaded"],components:["watchComponents"]}}};Re.style=Ze+Ve;export{Re as facephi_sdk_provider};
