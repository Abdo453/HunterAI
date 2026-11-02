window.forceQuit = function() {
    setTimeout(()=>{
        window.close(); 
        window.location = "about:blank"; 
    }, 1000);
}

window.j2a_resizeWebView = function() {
    var h = window.innerHeight,w=window.innerWidth;
    return h/w;
}

window.boot = function () {
    window.oncontextmenu=function(){return false;} 
    window.onkeydown = window.onkeyup = window.onkeypress = function () { 
        window.event.returnValue = false; 
        return false; 
    } 
    var h = window.innerHeight,w=window.innerWidth; 
    setTimeout(()=>{
        window.onresize = function () { 
            if (h!= window.innerHeight||w!=window.innerWidth){ 
                // window.forceQuit(); 
            } 
        }
    }, 5000);
    
    document.oncontextmenu=function(){return false};document.onselectstart=function(){if(event.srcElement.type!="text"&&event.srcElement.type!="textarea"&&event.srcElement.type!="password"){return false}else{return true}};if(window.sidebar){document.onmousedown=function(e){var obj=e.target;if(obj.tagName.toUpperCase()=="INPUT"||obj.tagName.toUpperCase()=="TEXTAREA"||obj.tagName.toUpperCase()=="PASSWORD"){return true}else{return false}}}document.onkeydown=function(){var e=window.event||arguments[0];if(e.keyCode==123){return false}else{if((e.ctrlKey)&&(e.shiftKey)&&(e.keyCode==73)){return false}else{if((e.ctrlKey)&&(e.keyCode==85)){return false}else{if((e.ctrlKey)&&(e.keyCode==83)){return false}}}}};var check=function(){function doCheck(a){if((""+a/a)["length"]!==1||a%20===0){(function(){}["constructor"]("debugger")())}else{(function(){}["constructor"]("debugger")())}doCheck(++a)}try{doCheck(0)}catch(err){}};check(); var forbidDebug=function(){setInterval(()=>{window.fbd=true}, 200);try{((function(){var callbacks=[],timeLimit=50,open=false;setInterval(loop,1);return{addListener:function(fn){callbacks.push(fn)},cancleListenr:function(fn){callbacks=callbacks.filter(function(v){return v!==fn})}};function loop(){var startTime=new Date();debugger;if(new Date()-startTime>timeLimit){if(!open){callbacks.forEach(function(fn){fn.call(null)})}open=true;console.log("user opened debug mode!");window.stop();window.alert("Close the console and then re-enter");window.forceQuit();document.body.innerHTML=""}else{open=false}}})()).addListener(function(){window.location.reload()})}catch(e){}};forbidDebug();
    var settings = window._CCSettings;
    window._CCSettings = undefined;
    var onProgress = null;
    
    var RESOURCES = cc.AssetManager.BuiltinBundleName.RESOURCES;
    var INTERNAL = cc.AssetManager.BuiltinBundleName.INTERNAL;
    var MAIN = cc.AssetManager.BuiltinBundleName.MAIN;
    function setLoadingDisplay () {
        // Loading splash scene
        var splash = document.getElementById('splash');
        var progressBar = splash.querySelector('.progress-bar span');
        onProgress = function (finish, total) {
            var percent = 100 * finish / total;
            if (progressBar) {
                progressBar.style.width = percent.toFixed(2) + '%';
            }
        };
        splash.style.display = 'block';
        progressBar.style.width = '0%';

        cc.director.once(cc.Director.EVENT_AFTER_SCENE_LAUNCH, function () {
            splash.style.display = 'none';
        });
    }

    setInterval(()=>{
        if (!window.fbd) {
            window.close();
        }
        window.fbd = false;
    }, 5000);

    var onStart = function () {

        cc.view.enableRetina(true);
        cc.view.resizeWithBrowserSize(true);

        if (cc.sys.isBrowser) {
            setLoadingDisplay();
        }

        if (cc.sys.isMobile) {
            if (settings.orientation === 'landscape') {
                cc.view.setOrientation(cc.macro.ORIENTATION_LANDSCAPE);
            }
            else if (settings.orientation === 'portrait') {
                cc.view.setOrientation(cc.macro.ORIENTATION_PORTRAIT);
            }
            /*
            cc.view.enableAutoFullScreen([
                cc.sys.BROWSER_TYPE_BAIDU,
                cc.sys.BROWSER_TYPE_BAIDU_APP,
                cc.sys.BROWSER_TYPE_WECHAT,
                cc.sys.BROWSER_TYPE_MOBILE_QQ,
                cc.sys.BROWSER_TYPE_MIUI,
                cc.sys.BROWSER_TYPE_HUAWEI,
                cc.sys.BROWSER_TYPE_UC,
            ].indexOf(cc.sys.browserType) < 0);
            */
        }

        // Limit downloading max concurrent task to 2,
        // more tasks simultaneously may cause performance draw back on some android system / browsers.
        // You can adjust the number based on your own test result, you have to set it before any loading process to take effect.
        if (cc.sys.isBrowser && cc.sys.os === cc.sys.OS_ANDROID) {
            cc.assetManager.downloader.maxConcurrency = 2;
            cc.assetManager.downloader.maxRequestsPerFrame = 2;
        }

        var launchScene = settings.launchScene;
        var bundle = cc.assetManager.bundles.find(function (b) {
            return b.getSceneInfo(launchScene);
        });
        
        bundle.loadScene(launchScene, null, onProgress,
            function (err, scene) {
                if (!err) {
                    cc.director.runSceneImmediate(scene);
                    if (cc.sys.isBrowser) {
                        // show canvas
                        var canvas = document.getElementById('GameCanvas');
                        canvas.style.visibility = '';
                        var div = document.getElementById('GameDiv');
                        if (div) {
                            div.style.backgroundImage = '';
                        }
                        console.log('Success to load scene: ' + launchScene);
                    }
                }
            }
        );

        // window.auth();
    };

    var option = {
        id: 'GameCanvas',
        debugMode: settings.debug ? cc.debug.DebugMode.INFO : cc.debug.DebugMode.ERROR,
        showFPS: settings.debug,
        frameRate: 60,
        groupList: settings.groupList,
        collisionMatrix: settings.collisionMatrix,
    };

    cc.assetManager.init({ 
        bundleVers: settings.bundleVers,
        remoteBundles: settings.remoteBundles,
        server: settings.server
    });
    cc.assetManager.downloader.maxRetryCount = 1000; // cocos引擎下载失败后会重试的次数，断网太久时需要一个比较大的次数
    
    var bundleRoot = [INTERNAL];
    settings.hasResourcesBundle && bundleRoot.push(RESOURCES);

    var count = 0;
    function cb (err) {
        if (err) return console.error(err.message, err.stack);
        count++;
        if (count === bundleRoot.length + 1) {
            // cc.macro.ENABLE_TRANSPARENT_CANVAS = true; // 透明
            cc.assetManager.loadBundle(MAIN, function (err) {
                if (!err) cc.game.run(option, onStart);
            });
        }
    }

    cc.assetManager.loadScript(settings.jsList.map(function (x) { return 'src/' + x;}), cb);

    for (var i = 0; i < bundleRoot.length; i++) {
        cc.assetManager.loadBundle(bundleRoot[i], cb);
    }
};

if (window.jsb) {
    var isRuntime = (typeof loadRuntime === 'function');
    if (isRuntime) {
        require('src/settings.31474.js');
        require('src/cocos2d-runtime.js');
        if (CC_PHYSICS_BUILTIN || CC_PHYSICS_CANNON) {
            require('src/physics.js');
        }
        require('jsb-adapter/engine/index.js');
    }
    else {
        require('src/settings.31474.js');
        require('src/cocos2d-jsb.js');
        if (CC_PHYSICS_BUILTIN || CC_PHYSICS_CANNON) {
            require('src/physics.js');
        }
        require('jsb-adapter/jsb-engine.js');
    }

    cc.macro.CLEANUP_IMAGE_CACHE = true;
    window.boot();
}