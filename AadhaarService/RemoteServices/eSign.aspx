<%@ Page Language="C#" AutoEventWireup="true" CodeFile="eSign.aspx.cs" Inherits="eSign" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>eSign</title>
    <link rel="stylesheet" href="css/bootstrap.css"/>
<style type="text/css">
.hdrbdr{padding-top:25px; background-color:#CCC;}
.gap{margin-top:5px;}
.gap1{margin-top:25px;}
.dwn{margin-top:15px;}
.flat{border-radius:0px;}
.set{margin-top:15px; margin-right:-140px;}
.set1{margin-top:15px; float:right;}
/*.txtclr{color: #F63;}
.clrtxt{color:#06F;}
*/
</style>
<script type="text/javascript" src="js/jquery-1.11.1.min.js"></script>
<script type="text/javascript" src="js/bootstrap.min.js"></script>
</head>
<body>
<form id="form2" runat="server">
<asp:Panel ID="SuccessMessagePanel" runat="server" CssClass="hide"  EnableViewState="false">
<div class="alert alert-success">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Success!</strong> OTP generated SuccessFully.
</div>
</asp:Panel>
<asp:Panel ID="FailMessagePanel" runat="server" CssClass="hide"  EnableViewState="false">
<div class="alert alert-danger">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Failed!</strong> Something went wrong.
  </div>
</asp:Panel>
<asp:Panel ID="EmptyAadharPanel" runat="server" CssClass="hide"  EnableViewState="false">
<div class="alert alert-info fade in">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Info!</strong> Aadhaar Number cannot be empty.
  </div>
</asp:Panel>
<div class="container-fluid">
<div class="row">
<div class="col-md-12">
<div class="col-md-8">
<img src="e-Sign.png" class="img-responsive" width="150">
</div>
<div class="col-md-2">
<img src="negp-logo.jpg" class="img-responsive pull-right set" width="120"/></div>
<div class="col-md-2">
<img src="uid-logo.jpg" class="img-responsive set1" width="60"/></div>
</div></div>
<div class="row hdrbdr"></div>
<div class="col-md-12 dwn">
<div class="col-md-3"></div>
<div class="col-md-6">
<div class="panel panel-default">
<div class="panel-body">
<div class="col-sm-6">Aadhaar Number</div>
<div class="col-sm-6"><asp:TextBox ID="txtaadhar" runat="server" class="form-control flat" MaxLength="12"></asp:TextBox></div>
<div class="col-sm-6 gap">OTP</div>
<div class="col-sm-3 gap"><asp:Button ID="btngenerateotp" runat="server" 
        Text="Generate OTP" class="btn btn-warning" onclick="btngenerateotp_Click"/></div>
<div style="padding-left: 0px;" class="col-sm-3 gap"><asp:TextBox ID="txtotp" runat="server" class="form-control flat"></asp:TextBox></div>
<div class="col-sm-6 gap">MIME Type</div>
<div class="col-sm-6 gap"><asp:TextBox ID="txtmimetype" runat="server" class="form-control flat"></asp:TextBox></div>
<div class="col-sm-6 gap">Document</div>
<div class="col-sm-6 gap"><asp:FileUpload ID="uploadpdf" runat="server" class="flat" /></div>
<div class="col-sm-5"></div>
<div class="col-sm-2 gap1"><asp:Button ID="btnsubmit" runat="server" Text="Submit" 
onclick="btnsubmit_Click" class="btn btn-warning"/></div>
<div class="col-sm-5"></div>
</div>
</div>
</div>
<div class="col-md-3"></div>
</div>
</div><!-- container-fluid -->
<div class="container text-center">
<asp:Literal ID="Literal1" runat="server"></asp:Literal>
</div>
</form>
</body>
</html>
