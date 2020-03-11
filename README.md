# Apache-Struts-v3

Script contiene la fusión de 3 vulnerabilidades de tipo RCE sobre ApacheStruts, además tiene la capacidad de crear shell servidor.


## SHELL
**php** `Funcion Terminada :)`
**jsp** `Funcion en desarrollo.`

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
Esta funcionalidad es efectiva cuando el servidor no tiene conexion a internet de tal manera que no podemos subir un archivo y la mejor opcion seria crear un archivo ya estando dentro.

<p align="center">
  <img src="https://github.com/s1kr10s/Apache-Struts-v3/blob/master/shell.jpg" width="550" alt="accessibility text">
</p>

Thanks.
