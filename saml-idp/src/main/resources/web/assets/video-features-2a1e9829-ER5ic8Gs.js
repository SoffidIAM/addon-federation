import{L as t}from"./index-KWd1MSP6.js";/*!
 * Built with Stencil
 * Copyright (c) 2025 Facephi Biometria, S.A.
 */const s="video-features-utils";function u(r,o,e){e.pause();const a=r.getVideoTracks()[0],c=a.getCapabilities?a.getCapabilities():a.getSettings();if(t.printDebug(s,"Selected Camera to play with id: ",c.deviceId,"name: ",a.label,"facingMode: ",c.facingMode),e.onloadeddata=()=>{e.play().then(()=>{t.printDebug(s,`Camera streaming success. New camera with id: ${c.deviceId}`)}).catch(i=>{t.printDebug(s,"Camera streaming unsuccess."),t.printDebug(s,i)})},e.srcObject=null,e.srcObject=r,o){const i=o.getVideoTracks();for(const g of i)g.stop()}}export{u as s};
