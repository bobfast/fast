<?php include("./dbcon_fast.php");
$configJson = json_decode(file_get_contents('./config.json'), true);
?>
<!DOCTYPE html>
<html lang="en">

<head>
<style>	#loader {display:none;z-index:999;width:100%;height:100%;position:fixed;top:0;left:0;background:#000;opacity:.5;}
		#loader span {position: absolute;top: 50%;left: 50%;transform: translate(-50%, -50%);display: inline-block;color:#fff;font-weight:bold;}</style>
   <script>	
	var renderedImg = new Array;

	var contWidth = 200, // 너비(mm) (a4에 맞춤)
		 padding = 5; //상하좌우 여백(mm)

	function createPdf() { //이미지를 pdf로 만들기
		document.getElementById("loader").style.display = "block"; //로딩 시작

		var lists = document.querySelectorAll("div.pdfArea > li"),
			 deferreds = [],
			 doc = new jsPDF("p", "mm", "a4"),
			 listsLeng = lists.length;

		for (var i = 0; i < listsLeng; i++) { // li 개수만큼 이미지 생성
			var deferred = $.Deferred();
			deferreds.push(deferred.promise());
			generateCanvas(i, doc, deferred, lists[i]);
		}

		$.when.apply($, deferreds).then(function () { // 이미지 렌더링이 끝난 후
			var sorted = renderedImg.sort(function(a,b){return a.num < b.num ? -1 : 1;}), // 순서대로 정렬
				 curHeight = padding, //위 여백 (이미지가 들어가기 시작할 y축)
				 sortedLeng = sorted.length;
			for (var i = 0; i < sortedLeng; i++) {
				var sortedHeight = sorted[i].height, //이미지 높이
					 sortedImage = sorted[i].image; //이미지

				if( curHeight + sortedHeight > 297 - padding * 2 ){ // a4 높이에 맞게 남은 공간이 이미지높이보다 작을 경우 페이지 추가
					doc.addPage(); // 페이지를 추가함
			curHeight = padding; // 이미지가 들어갈 y축을 초기 여백값으로 초기화
					doc.addImage(sortedImage, 'jpeg', padding , curHeight, contWidth, sortedHeight); //이미지 넣기
					curHeight += sortedHeight; // y축 = 여백 + 새로 들어간 이미지 높이
				} else { // 페이지에 남은 공간보다 이미지가 작으면 페이지 추가하지 않음
					doc.addImage(sortedImage, 'jpeg', padding , curHeight, contWidth, sortedHeight); //이미지 넣기
					curHeight += sortedHeight; // y축 = 기존y축 + 새로들어간 이미지 높이
				}
			}
			doc.save('pdf_test.pdf'); //pdf 저장

			document.getElementById("loader").style.display = "none"; //로딩 끝
			curHeight = padding; //y축 초기화
			renderedImg = new Array; //이미지 배열 초기화
		});
	}

	function generateCanvas(i, doc, deferred, curList){ //페이지를 이미지로 만들기
		var pdfWidth = $(curList).outerWidth() * 0.2645, //px -> mm로 변환
			 pdfHeight = $(curList).outerHeight() * 0.2645,
			 heightCalc = contWidth * pdfHeight / pdfWidth; //비율에 맞게 높이 조절
		html2canvas( curList ).then(
			function (canvas) {
				var img = canvas.toDataURL('image/jpeg', 1.0); //이미지 형식 지정
				renderedImg.push({num:i, image:img, height:heightCalc}); //renderedImg 배열에 이미지 데이터 저장(뒤죽박죽 방지)     
				deferred.resolve(); //결과 보내기
			 }
		);
	}
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

<body>
	<div id="loader"><span>잠시만 기다려주세요...</span></div>
	
	<div class="wrap">
		<div class="pdfArea">
			  <li>
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
            <a href="cuckoo.php">
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
<?php
	$query ="select * from attack_index where no=1";
	$result=mysqli_query($db,$query);
	while($data=mysqli_fetch_array($result)) {
?>
        <br>
        <span style="font-style: italic ; font-weight: bold; font-size: 3em;line-height: 1.0em; font-family: arial; color:black;">Fast-Monitor Report</span>
        <br>
        <h2><i class="fa fa-angle-right"></i> #1 Attack (pid:<?=$data["pid"]?>, <?=$data["time_stamp"]?>)</h2>
<?php }?>   <button type="button" onclick="createPdf()">PDF 만들기</button><br><br>
     <div class="row">
          <div class="col-md-12">
            <div class="content-panel">
              <table class="table">
                <thead>
                  <tr>
                    <th>IDX</th>
                    <th>Attacker PID</th>
                    <th>Address</th>
                    <th>Size</th>
                    <th>Windows API</th>
                  </tr>
                </thead>
                <tbody>
<?php 
	$query="select * from api_status where idx=1";
	$result=mysqli_query($db,$query);
	while($data =mysqli_fetch_array($result)) {
?>
	
                  <tr>
                    <td>1</td>
                    <td><?=$data["caller_pid"]?></td>
                    <td><?=$data["address"]?></td>
                    <td><?=$data["size"]?></td>
                    <td><?=$data["wapi"]?></td>
                  </tr>
<?php }?>
            
                </tbody>
              </table>
            </div>
          </div>
        </div>
<?php
	$query ="select * from attack_index where no=1";
	$result=mysqli_query($db,$query);
	while($data=mysqli_fetch_array($result)){ 
?>
          <h4><i class="fa fa-angle-right"></i> Code Section Hashing</h4>
          <div class="row">
            <div class="col-md-12">
              <div class="content-panel">
                <h4><i class="fa fa-angle-right"></i>  <?=$data["hashcheck"]?></h4>
  <?php }?>              
                
              </div>
            </div>
          </div>
  
          <h4><i class="fa fa-angle-right"></i> Excution Code Dump</h4>
          <div class="row">
            <div class="col-md-12">
              <div class="content-panel">
	            <?php
		            $query ="select * from dump_path where idx=1";
		            $result=mysqli_query($db,$query);
		            while($data=mysqli_fetch_array($result)){?> 
                  <h4><i class="fa fa-angle-right"></i> <?=$data["dump"]?></h4>
                  <?php 
                    $fp = fopen($configJson["dump"] . $data["dump"],'w');
                    while( !feof($fp) ) {
                      echo fgets($fp);
                    }
                    fclose($fp);
                  }?>
                
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
</li>
</div>
</div>
</body>
</html>
