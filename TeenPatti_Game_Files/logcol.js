function getQuery(name) {

    if (!name || !window.location || !window.location.search) return null;

    const currentUrl = new URL(window.location.href);
    const searchParams = new URLSearchParams(currentUrl.search);
    let result = searchParams && searchParams.get(name);

    return result && decodeURIComponent(result);
    
}

function getlcTimeZone(){

    let offsetMinutes = new Date().getTimezoneOffset()
    let offsetHours = Math.abs(Math.floor(offsetMinutes/60))
    // let offsetSign = offsetMinutes > 0 ? '+':'-'
    let offsetSign = offsetMinutes > 0 ? '-':'+'
    offsetMinutes = Math.abs( offsetMinutes % 60 )
    return 'GMT' + offsetSign + offsetHours.toString().padStart(2,'0') + ':' + offsetMinutes.toString().padStart(2,'0') + 
            Intl.DateTimeFormat().resolvedOptions().timeZone + ' ' +  Intl.DateTimeFormat().resolvedOptions().locale + ' ' + Intl.DateTimeFormat().resolvedOptions().numberingSystem
}

function getGameName(){

    let pathArray = window.location.pathname.split('/')
    return pathArray[2]

}

function getUids(jsonBody){

        // fetch("https://dev.nonon.top:8888/hgameadmin/logcol/add", {
        // fetch("https://localhost:8888/hgameadmin/logcol/add", {
            // fetch("http://localhost:8888/hgameadmin/logcol/add", {
                    // fetch("http://localhost:8888/hgameadmin/logcol/add", {
        fetch("https://dev.nonon.top/hgameadmin/logcol/adduids", {
            method:'POST',
            // body:jsonBody,
            body:JSON.stringify(jsonBody),
            headers:{"Content-Type":'application/json;charset=utf-8'}
        }).then(
            res=> {
                originalConsoleLog10("logcol success")
            }
        ).catch(
            err=>{
                originalConsoleLog10(err)
            }
        )

}

function getcliloc(){

    let url = 'https://dev.nonon.top/getcliloc/'

    fetch(url,{
        method:'GET',
        // headers:{"Content-Type":'application/json;charset=UTF-8'}
        headers:{"Content-Type":'text/plain; charset=utf-8'}
    }).then(res=>{
        // console.log(res.text().then(res=>{console.log(res);}))
    //   console.log(res.text().then(res=>console.log(res)))
    res.text().then(res=>{
        window.cliloc = encodeURIComponent(res)
        // let sdkConfig = JSON.parse(res)
        // enableLog = sdkConfig.apps.default.extra?.logConfig.enableLog
        // logUids = sdkConfig.apps.default.extra.logConfig.logUids
    }
    ).catch(err => console.log(err))
    }).catch(err=>{
        console.log(err)
    })

}

function logcol(msg,type){

    // let sdk = getQuery('sdk') || 'empty';
    // let uid = window.user.uid || getQuery('uid') || 'empty';
    // let token = window.user.token || getQuery('token') || 'empty';
    // let gameId = window.user.extra.gameId || 'empty'
    // let gameName = window.user.extra.gameName || getGameName() || 'empty';
    // // let gameId = window.user.extra.gameId || 'empty'
    // let lang = window.user.lang || getQuery('lang') || 'empty'
    // let href = window.location.href;
    // let ua = window.user.ua;
    // let jsonBody = {sdk:sdk,uid:uid,token:token,gameId:gameId,gameName:gameName,lang:lang,href:href,ua:ua,msg:encodeURIComponent(msg),type:type}
    // let jsonBody = {msg:encodeURIComponent(msg),type:type,}
  	try{
	let jsonBody = {msg:JSON.stringify(msg),type:type,}
    	msgdata.push(encodeURIComponent(JSON.stringify(jsonBody)))
	}catch(e){
	originalConsoleLog10(e)
	}
    // fetch("https://dev.nonon.top/hgameadmin/logcol/add", {
    //     method:'POST',
    //     body:JSON.stringify(jsonBody),
    //     headers:{"Content-Type":'application/json;charset=utf-8'}
    // }).then(
    //    res=> {
    //         originalConsoleLog("logcol success")
    //    }
    // ).catch(
    //     err=>{
    //         originalConsoleLog(err)
    //     }
    // )

}

function logcol0(){

    // if(msgdata.length<10) return
    if(msgdata.length<=0) return
    if(!enableLog) return
    if(!continueLog&&logUids?.length > 0){
        // if(continueLog||logUids?.length > 0){
        let uid = window.user?.uid || getQuery('uid') || 'empty';
        // let continueLog = false;
        logUids.forEach(
            ele =>{
                if (ele==uid) continueLog = true
            }
        )
        if(! continueLog) return
    }

    continueLog = true
    let msg0 = msgdata
    msgdata = []
    let msgBody = ''
    msg0.forEach(ele => msgBody = msgBody + '=>' + ele )
    msg0 = []

    let sdk = getQuery('sdk') || 'empty';
    let uid = window.user?.uid || getQuery('uid') || 'empty';
    let token = window.user?.token || getQuery('token') || 'empty';
    let gameId = window.user?.extra.gameId || 'empty'
    let gameName = window.user?.extra.gameName || getGameName() || 'empty';
    // let gameId = window.user.extra.gameId || 'empty'
    let lang = window.user?.lang || getQuery('lang') || 'empty'
    let href = window.location.href;
    let ua = window.user?.ua||window.navigator?.userAgent;
    let requestTime = new Date().toLocaleString() + getlcTimeZone();
    // let jsonBody = {sdk:sdk,uid:uid,token:token,gameId:gameId,gameName:gameName,lang:lang,href:href,ua:ua,msg:encodeURIComponent(msgBody),type:type}
    let jsonBody = {sdk:sdk,uid:uid,token:token,gameId:gameId,gameName:gameName,lang:lang,href:href,ua:ua,msg:decodeURIComponent(msgBody),requestTime:requestTime,ip:window.cliloc}
    // let jsonBody = {sdk:sdk,uid:uid,token:token,gameId:gameId,gameName:gameName,lang:lang,href:href,ua:ua,msg:decodeURIComponent(msgBody),type:type}

    if(logUids?.length>0){
	getUids(jsonBody);
	return;
    }

    // fetch("https://dev.nonon.top:8888/hgameadmin/logcol/add", {
        // fetch("https://localhost:8888/hgameadmin/logcol/add", {
            // fetch("http://localhost:8888/hgameadmin/logcol/add", {
                    // fetch("http://localhost:8888/hgameadmin/logcol/add", {
    fetch("https://dev.nonon.top/hgameadmin/logcol/add", {
        method:'POST',
        // body:jsonBody,
        body:JSON.stringify(jsonBody),
        headers:{"Content-Type":'application/json;charset=utf-8'}
    }).then(
       res=> {
            originalConsoleLog10("logcol success")
       }
    ).catch(
        err=>{
            originalConsoleLog10(err)
        }
    )
}

let originalConsoleLog10 = window.console.log;
let originalConsoleInfo = window.console.info;
let originalConsoleWarn = window.console.warn;
let originalConsoleError = window.console.error;
let msgdata = [];
let enableLog = false;
let logUids = [];
let continueLog = false;

function LogConsole() {

    // let originalConsoleLog = window.console.log;
    // let originalConsoleInfo = window.console.info;
    // let originalConsoleWarn = window.console.warn;
    // let originalConsoleError = window.console.error;
    // let msgdata = [];

    let myConsoleLog = function(...msg){
        // window.console.log("Inject console success!! ",msg)
        // windowConsoleLog
        // originalConsoleLog("Inject Console success!! ", msg)
        // originalConsoleLog("", msg)
        originalConsoleLog10(...msg)
        // msgdata.push(msg);
        logcol(msg,'normal')

    }
    let myConsoleWarn = function(...msg){

        // originalConsoleWarn("Inject Console success!! ", msg)
        originalConsoleWarn(...msg)
        // msgdata.push(msg);
      //  logcol(msg,'warn')

    }
    let myConsoleError = function(...msg){

        // originalConsoleError("Inject Console success!! ", msg)
        originalConsoleError(...msg)
        // msgdata.push(msg);
        logcol(msg,'error')

    }
    let myConsoleInfo = function(...msg){

        // originalConsoleInfo("Inject Console success!! ", msg)
        originalConsoleInfo(...msg)
        // msgdata.push(msg);
        logcol(msg,'info')

    }

    window.console.log = myConsoleLog;
    window.console.info = myConsoleInfo;
    window.console.warn = myConsoleWarn;
    window.console.error = myConsoleError;
    console.log = myConsoleLog;
    console.warn = myConsoleInfo;
    console.warn = myConsoleWarn;
    console.error = myConsoleError;

}

function logcat(){

    // window.addEventListener('error', (e)=>{
    window.addEventListener('error', (e)=>{
        // logcol(JSON.stringify(e.message))
        // logcol(JSON.stringify(e.error),'error')
        logcol(JSON.stringify(e.error.stack),'listenerror')
        originalConsoleLog10("error catch: ",  e.message)
    }
    )

    // window.addEventListener('unhandledRejection',(e)=>{
    window.addEventListener('unhandledrejection',(e)=>{
        // logcol(JSON.stringify(e.reason.message),'error')
        logcol(JSON.stringify(e.reason.stack),'rejecterror')
        originalConsoleLog10('unhandledrejection catch: ', e.reason)
        // console.log('unhandledRejection catch: ', e)
    })
    
}

function logCircle(){
    setInterval(
        logcol0,5*1000
    )
    setInterval(
        logClear,30*1000
    )
}

function LogConfig(){

    let host = window.location.hostname;
    let sdk = getQuery('sdk');
    let url = 'https://' + `${host}/config/sdk/${sdk}/${sdk}` + '.json?v=v1.0.8&timestamp=' + new Date().getTime() 

               // fetch('https://cdn-web.hotgame.win/config/sdk/higo/higo.json?v=v1.0.8.1&timestamp=1742385039785',{
                // fetch('https://dev.nonon.top/config/sdk/ximi/ximi.json?v=v1.0.8',{
                fetch(url,{
                    method:'GET',
                    headers:{"Content-Type":'application/json;charset=UTF-8'}
                }).then(res=>{
                    // console.log(res.text().then(res=>{console.log(res);})) 
                //   console.log(res.text().then(res=>console.log(res))) 
                res.text().then(res=>{
                    let sdkConfig = JSON.parse(res)
                    enableLog = sdkConfig.apps.default.extra?.logConfig.enableLog
                    logUids = sdkConfig.apps.default.extra.logConfig.logUids
                }
                ).catch(err => console.log(err))
                }).catch(err=>{
                    console.log(err)
                })

		getcliloc()
}

function logClear(){
    if(!enableLog||!continueLog) msgdata=[]
}

LogConsole()
LogConfig()
logCircle()
logcat()
