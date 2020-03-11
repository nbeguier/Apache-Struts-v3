# Apache-Struts-v3

Script contains the fusion of 3 vulnerabilities of type RCE on ApacheStruts, also has the ability to create server shell.

## Prerequisites

```
pip3 install -r requirements.txt
```

## SHELL
**php** `Finished :)`
**jsp** `In development.`

## CVE ADD
**CVE-2013-2251**  `'action:', 'redirect:' and 'redirectAction'`
```bash
docker run --rm --name struts2 -p 8080:8080 2d8ru/struts2
# try: http://localhost:8080/S2-016/default.action
```

**CVE-2017-5638**  `Content-Type`
```bash
docker run --rm --name struts2 -p 8080:8080 2d8ru/struts2
# try: http://localhost:8080/S2-033/orders
```
**CVE-2018-11776** `'redirect:' and 'redirectAction'`


<p align="center">
  <img src="https://github.com/s1kr10s/Apache-Struts-v3/blob/master/screen.png" width="600" alt="accessibility text">
</p>


## Upload Shell
This functionality is effective when the server has no internet connection so that we can not upload a file and the best option would be to create a file already being inside.

<p align="center">
  <img src="https://github.com/s1kr10s/Apache-Struts-v3/blob/master/shell.jpg" width="550" alt="accessibility text">
</p>

Thanks.
