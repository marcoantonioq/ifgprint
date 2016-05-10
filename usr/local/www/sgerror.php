<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Proibido o Acesso</title>
<style type="text/css">
#site {width: 100%; height: 100%; alignment-adjust: middle;}

body {
  font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
  font-size: 14px;
  color: #000;
  text-align:center;
}

.titulo {
  font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
  font-size: 36px;
  color: #C10F0F;
}

.txt_site {
  font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
  font-size: 14px;
  color: #F00;
}

#box {
  height: 500px;
  width: 800px;
  top: 50%;
  left: 50%;
  margin-top: -250px;
  margin-left: -400px;
  position: absolute;
  border: 0px solid black;
}

.foolter {
  position: absolute;
  bottom: 0px;
  width: 100%;
}

</style>
</head>
<body>
<div id="box">
<h1 class="titulo">O acesso foi negado!</h1>
<p><img src="./img/deny.png" /></p>

O site: <span class="txt_site"><?php echo $_GET['u']; ?></span>,
<br>é considerado impróprio ou não homologado para uso.


</p>Em caso de dúvidas, por favor consulte a TI pelo telefone (64)3371-9166 ou envie email para
</p><a href="mailto:suporte.goias@ifg.edu.br">suporte.goias@ifg.edu.br</a><br> 

</div>

<div class="foolter">
  IFG Câmpus Cidade de Goiás <br />
  Quartel do XX, Praça Brasil Ramos Caiado, S/Nº, Centro. CEP: 76600-000. Goiás, GO <br />
  Telefone: (62) 3371-9150 <br />
</div>

</body>
</html>
