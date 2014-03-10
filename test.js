//var cs = require("./browser.js");
var cs = require("./node.js");

// dummy functions
cs.install({CSets:{},pdecode:function(){console.log("pdecode",arguments);return {}},pencode:function(){console.log("pencode",arguments);return new Buffer(0)}});

var a = {parts:{}};
var b = {parts:{}};
cs.genkey(a,function(){
  console.log("genkey",a);
  cs.genkey(b,function(){
    console.log("genkey",b);
    var id = {cs:{"1a":{}}};[]
    cs.loadkey(id.cs["1a"],a["1a"],a["1a_secret"]);
    var to = {};
    cs.loadkey(to,b["1a"]);
    console.log(id,to);
    var open = cs.openize(id,to,{});
    console.log("opened",open);
  });
});
