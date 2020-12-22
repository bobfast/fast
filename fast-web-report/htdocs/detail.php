<?php include("./dbcon_fast.php");
$configJson = json_decode(file_get_contents('./config.json'), true);
$cuckooUrl = $configJson["cuckoo"] . "analysis/";
?>
<!DOCTYPE html>
<html lang="en">

<head>
<script type = "text/javascript" src = "http://code.jquery.com/jquery-latest.min.js"></script> 
<script type = "text/javascript" src = "https://cdnjs.cloudflare.com/ajax/libs/jspdf/1.5.3/jspdf.min.js"></script>
<script type = "text/javascript" src = "https://html2canvas.hertzen.com/dist/html2canvas.min.js"></script>
<script src="http://cdn.jquerytools.org/1.2.5/jquery.tools.min.js"></script>
<script language="javascript" type="text/javascript">
$(function () {
$('#contents tr').hide(); -- class가 contents인  tr을 모두 감춘다.  펼쳐질 내용을 감춰두기위한 작업
$('#contents').find('.title').parent().show();
-- class가 title인 td가 속한 tr을  보이기위한 작업(parent는 상위를 의미한다.)
$('#contents .title').parent().click(function(){ -- class가 title인 td가 속한 tr을 클릭하면 함수 실행
$('#contents tr').hide();
$('#contents').find('.title').parent().show();
$('#contents').find('.title').css('background-color', '#fff'); -- class가 title인 td가 속한 tr에 배경색을 흰색으로 지정
var tr = $('#contents tr');
var rindex = $(this).parent().children().index(this); -- 클릭한 tr의 인덱스를 찾아 변수에 저장
$(this).children().css('background-color', '#f7f7f7'); -- 클릭한 tr(제목)에만 배경색을 회색으로 지정
for(var i = rindex; i < rindex + 2; i++){ --  클릭한 tr의 다음(1이면 2) tr 인덱스를 찾기위한 작업
$(tr[i]).show(); -- 찾아낸 인덱스 tr을 보이기위한 작업
}
});
});
</script>


  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="">
  <meta name="author" content="Dashboard">
  <meta name="keyword" content="Dashboard, Bootstrap, Admin, Template, Theme, Responsive, Fluid, Retina">
  <title>Fast-Monitor Log</title>

  <!-- Favicons -->
  <link href="img/favicon.png" rel="icon">
  <link href="img/apple-touch-icon.png" rel="apple-touch-icon">

  <!-- Bootstrap core CSS -->
  <link href="lib/bootstrap/css/bootstrap.min.css" rel="stylesheet">
  <!--external css-->
  <link href="lib/font-awesome/css/font-awesome.css" rel="stylesheet" />
  <link rel="stylesheet" type="text/css" href="css/zabuto_calendar.css">
  <link rel="stylesheet" type="text/css" href="lib/gritter/css/jquery.gritter.css" />
  <!-- Custom styles for this template -->
  <link href="css/style.css" rel="stylesheet">
  <link href="css/style-responsive.css" rel="stylesheet">
  <script src="lib/chart-master/Chart.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bluebird/3.7.2/bluebird.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/1.5.3/jspdf.min.js"></script>
    <script src="https://unpkg.com/html2canvas@1.0.0-rc.5/dist/html2canvas.js"></script>
  <!-- =======================================================
    Template Name: Dashio
    Template URL: https://templatemag.com/dashio-bootstrap-admin-template/
    Author: TemplateMag.com
    License: https://templatemag.com/license/
  ======================================================= -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bluebird/3.7.2/bluebird.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/1.5.3/jspdf.min.js"></script>
    <script src="https://unpkg.com/html2canvas@1.0.0-rc.5/dist/html2canvas.js"></script>




</head>
<script>
  $(document).ready(function() {
    $('#savePdf').click(function() { // pdf저장 button id
        
        html2canvas($('#pdfDiv')[0]).then(function(canvas) { //저장 영역 div id
      
        // 캔버스를 이미지로 변환
        var imgData = canvas.toDataURL('image/jpeg');
           
        var imgWidth = 190; // 이미지 가로 길이(mm) / A4 기준 210mm
        var pageHeight = imgWidth * 1.414;  // 출력 페이지 세로 길이 계산 A4 기준
        var imgHeight = canvas.height * imgWidth / canvas.width;
        var heightLeft = imgHeight;
        var margin = 10; // 출력 페이지 여백설정
        var doc = new jsPDF('p', 'mm');
        var position = 0;
           
        // 첫 페이지 출력
        doc.addImage(imgData, 'jpeg', margin, position, imgWidth, imgHeight);
        heightLeft -= pageHeight ;
             
        // 한 페이지 이상일 경우 루프 돌면서 출력
        while (heightLeft >= 0) {
            position = heightLeft - imgHeight;
            doc.addPage();
            doc.addImage(imgData, 'jpeg', margin, position, imgWidth, imgHeight);
            heightLeft -= pageHeight;
        }
     
        // 파일 저장
        doc.save('file-name.pdf');
  
        
    });
  
    });
    
    
  })
  
  
  
  </script>
<body>

<script type = "text/javascript" src = "https://cdnjs.cloudflare.com/ajax/libs/jspdf/1.5.3/jspdf.min.js"></script>
    <script type = "text/javascript" src = "https://html2canvas.hertzen.com/dist/html2canvas.min.js"></script>
    <script type = "text/javascript" src = "http://code.jquery.com/jquery-latest.min.js"></script>
  <section id="container">
    <!-- **********************************************************************************************************************************************************
        TOP BAR CONTENT & NOTIFICATIONS
        *********************************************************************************************************************************************************** -->
    <!--header start-->
    <header class="header black-bg">
      <div class="sidebar-toggle-box">
        <div class="fa fa-bars tooltips" data-placement="right" data-original-title="Toggle Navigation"></div>
      </div>
      <!--logo start-->
      <a href="./" class="logo"><b><span>FAST-Monitor</span>&nbsp;Log</b></a>
      <!--logo end-->
    </header>
    <!--header end-->
    <!-- **********************************************************************************************************************************************************
        MAIN SIDEBAR MENU
        *********************************************************************************************************************************************************** -->
    <!--sidebar start-->
    <aside>
      <div id="sidebar" class="nav-collapse ">
        <!-- sidebar menu start-->
        <ul class="sidebar-menu" id="nav-accordion">
          <p class="centered"><img src="fast-logo.png" width="160"></p>
          <li class="mt">
            <a class="active" href="./">
              <i class="fa fa-dashboard"></i>
              <span>Fast Monitor</span>
              </a>
          </li>
          <li class="sub-menu">
          <a href="<?php echo $cuckooUrl;?>">
              <i class="fa fa-cogs"></i>
              <span>Cuckoo</span>
            </a>
          </li>
        </ul>
        <!-- sidebar menu end-->
      </div>
    </aside>
    <!--sidebar end-->
    <!-- **********************************************************************************************************************************************************
        MAIN CONTENT
        *********************************************************************************************************************************************************** -->
    <!--main content start-->
    <section id="main-content">
      <section class="wrapper">
      <?php 	$no=$_GET["no"]; 

if(file_exists('/csvfile.csv')) 
  { unlink('./csvfile.csv'); }
$newline = chr(10); 
$fp = fopen( "./csvfile.csv", "w" ) or die("./csvfile.csv File cannot open") ; 
$query ="select * from attack_index where no=$no";
$result=mysqli_query($db,$query);
while($data=mysqli_fetch_array($result)) {
  fwrite($fp, basename($data["procname"]));
  fwrite($fp,$newline);  
?>
      <br>
      <div id="pdfDiv">
      <span style="font-style: italic ; font-weight: bold; font-size: 3em;line-height: 1.0em; font-family: arial; color:black;">Fast-Monitor Report</span>
      <br>
      <h2><i class="fa fa-angle-right"></i> <?=basename($data["procname"])?> (pid:<?=$data["pid"]?>, <?=$data["time_stamp"]?>)</h2>
<?php }?>  <button type="button" class="btn btn-primary" id="savePdf" >PDF 저장</button> <button type="button" class="btn btn-primary" onclick="window.open('csvfile.csv')">CSV 저장</button><br><br>
   <div class="row">
        <div class="col-md-12">
          <div class="content-panel">
            <table class="table">
              <thead>
                <tr>
                  <th>IDX</th>
                  <th>Attacker PID</th>
                  <th>Attacker Path</th>
                  <th>Address</th>
                  <th>Size</th>
                  <th>Windows API</th>
                </tr>
              </thead>
              <tbody>
<?php 
$query="select * from api_status where idx=$no";
$result=mysqli_query($db,$query);

fwrite($fp,"IDX,Attacker PID,Attacker Path,Address,Size,Windows API");
fwrite($fp,$newline); 
$i = 1;
while($data =mysqli_fetch_array($result)) {
?>

                <tr>
                  <td><?php echo $i++;?></td>
                  <td><?=$data["caller_pid"]?></td>
                  <td><?=$data["caller_path"]?></td>
                  <td><?=$data["address"]?></td>
                  <td><?=$data["size"]?></td>
                  <td><details>
                    <summary><?=$data["wapi"]?></summary>
                    <!-- api call stack 넣는 부분-->
                    <p><?php
                    $content = nl2br($data["callstack"]);
                    echo $content;
                    ?></p>
                </details></td>
                </tr>

<?php 

  fwrite($fp,$data["idx"].",".$data["caller_pid"].",".$data["caller_path"].",".$data["address"].",".$data["size"].",".$data["wapi"]);
  fwrite($fp,$newline); 
}
?>
          
              </tbody>
            </table>
          </div>
        </div>
      </div>
<?php
$query ="select * from attack_index where no=$no";
$result=mysqli_query($db,$query);
fwrite($fp,"Hashing");
fwrite($fp,$newline); 
while($data=mysqli_fetch_array($result)){ 
?>
        <h4><i class="fa fa-angle-right"></i> Code Section Hashing</h4>
        <div class="row">
          <div class="col-md-12">
            <div class="content-panel">
            <table class="table table-hover">
              <h4><i class="fa fa-angle-right"></i>Compare Results</h4>
              <tbody>
                  <tr>
                    <td>>></td>
              <td><?php
    fwrite($fp,$data["hashcheck"]);
    $content = nl2br($data["hashcheck"]);
    echo $content;
    fwrite($fp,$newline);
  }?>  
            </tr>
                </tbody>
              </table>
            </td>
            </div>
          </div>
        </div>

        <h4><i class="fa fa-angle-right"></i> Excution Code Dump</h4>
        <div class="row">
          <div class="col-md-12">
            <div class="content-panel">
<?php
  $query ="select * from dump_path where idx=$no";
  $result=mysqli_query($db,$query);
  fwrite($fp,"Dump".",");
  fwrite($fp,$newline); 
  while($data=mysqli_fetch_array($result)){?> 
              <table class="table table-hover">
              <h4><i class="fa fa-angle-right"></i><?=$data["dump"]?></h4>
              <tbody>
                  <tr>
                    
                    <td>
              <!-- fast 위치를 바꾸어야함--><!-- fast 위치를 바꾸어야함--><!-- fast 위치를 바꾸어야함--><!-- fast 위치를 바꾸어야함-->
              <details>
                    <summary>Open</summary>
                    <!-- api call stack 넣는 부분-->
                    <p>                <?php
                fwrite($fp,$data["dump"]);
                fwrite($fp,$newline);
                $filename = $data["dump"];
                  $fn = $configJson["dump"] . "$filename";

                  if(file_exists($fn)){
                    $fpp = fopen($fn,"r");
                  } else {
                    echo "there is no file <br />";
                    exit;
                  }
                  $content = fread($fpp, filesize($fn));
                  fwrite($fp,$content);
                  $content = nl2br($content);
                  echo $content;
                  
                  fclose($fpp);
                  echo "<hr />";
                  ?>  </p>
                </details>
                <?php 
              fwrite($fp,$newline);
              fclose($fp);
              }?>
              </td>
                  </tr>
                </tbody>
              </table>
              </div>
            </div>
          </div>
        </div>
        <br>

      </section>
    </section>
    <!-- /MAIN CONTENT -->
    <!--main content end-->
    <!--footer start-->
    <footer class="site-footer">
      <div class="text-center">
        <p>
          &copy; Copyrights <strong>Dashio</strong>. All Rights Reserved
        </p>
        <div class="credits">
          <!--
            You are NOT allowed to delete the credit link to TemplateMag with free version.
            You can delete the credit link only if you bought the pro version.
            Buy the pro version with working PHP/AJAX contact form: https://templatemag.com/dashio-bootstrap-admin-template/
            Licensing information: https://templatemag.com/license/
          -->
          Created with Dashio template by <a href="https://templatemag.com/">TemplateMag</a>
        </div>
        <a href="./" class="go-top">
          <i class="fa fa-angle-up"></i>
          </a>
      </div>
    </footer>
    <!--footer end-->
  </section>
  <!-- js placed at the end of the document so the pages load faster -->
  <script src="lib/jquery/jquery.min.js"></script>

  <script src="lib/bootstrap/js/bootstrap.min.js"></script>
  <script class="include" type="text/javascript" src="lib/jquery.dcjqaccordion.2.7.js"></script>
  <script src="lib/jquery.scrollTo.min.js"></script>
  <script src="lib/jquery.nicescroll.js" type="text/javascript"></script>
  <script src="lib/jquery.sparkline.js"></script>
  <!--common script for all pages-->
  <script src="lib/common-scripts.js"></script>
  <script type="text/javascript" src="lib/gritter/js/jquery.gritter.js"></script>
  <script type="text/javascript" src="lib/gritter-conf.js"></script>
  <!--script for this page-->
  <script src="lib/sparkline-chart.js"></script>
  <script src="lib/zabuto_calendar.js"></script>
  <script type="application/javascript">
    $(document).ready(function() {
      $("#date-popover").popover({
        html: true,
        trigger: "manual"
      });
      $("#date-popover").hide();
      $("#date-popover").click(function(e) {
        $(this).hide();
      });

      $("#my-calendar").zabuto_calendar({
        action: function() {
          return myDateFunction(this.id, false);
        },
        action_nav: function() {
          return myNavFunction(this.id);
        },
        ajax: {
          url: "show_data.php?action=1",
          modal: true
        },
        legend: [{
            type: "text",
            label: "Special event",
            badge: "00"
          },
          {
            type: "block",
            label: "Regular event",
          }
        ]
      });
    });

    function myNavFunction(id) {
      $("#date-popover").hide();
      var nav = $("#" + id).data("navigation");
      var to = $("#" + id).data("to");
      console.log('nav ' + nav + ' to: ' + to.month + '/' + to.year);
    }
  </script>

</body>
</div>
</html>
