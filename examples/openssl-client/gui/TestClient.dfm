object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'https client example'
  ClientHeight = 441
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  OnCloseQuery = FormCloseQuery
  OnShow = FormShow
  DesignSize = (
    624
    441)
  TextHeight = 15
  object Memo1: TMemo
    Left = 8
    Top = 25
    Width = 585
    Height = 377
    Anchors = [akLeft, akTop, akRight, akBottom]
    Lines.Strings = (
      'Memo1')
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object Button1: TButton
    Left = 272
    Top = 408
    Width = 75
    Height = 25
    Anchors = [akLeft, akTop, akRight]
    Caption = 'Close'
    ModalResult = 8
    TabOrder = 1
    OnClick = Button1Click
  end
  object IdHTTP1: TIdHTTP
    IOHandler = IdSecIOHandlerSocketOpenSSL1
    HandleRedirects = True
    ProxyParams.BasicAuthentication = False
    ProxyParams.ProxyPort = 0
    Request.ContentLength = -1
    Request.ContentRangeEnd = -1
    Request.ContentRangeStart = -1
    Request.ContentRangeInstanceLength = -1
    Request.Accept = 'Application/txt'
    Request.BasicAuthentication = False
    Request.UserAgent = 'Mozilla/3.0 (compatible; Indy Library)'
    Request.Ranges.Units = 'bytes'
    Request.Ranges = <>
    HTTPOptions = [hoKeepOrigProtocol, hoNoProtocolErrorException, hoWantProtocolErrorContent]
    Left = 80
    Top = 40
  end
  object IdSecIOHandlerSocketOpenSSL1: TIdSecIOHandlerSocketOpenSSL
    MaxLineAction = maException
    Port = 0
    DefaultPort = 0
    SSLOptions.Method = sslvTLSv1_3
    SSLOptions.SSLVersions = [sslvTLSv1_3]
    SSLOptions.Mode = sslmClient
    SSLOptions.VerifyMode = []
    SSLOptions.VerifyDepth = 100
    OnStatusInfo = IdSecIOHandlerSocketOpenSSL1StatusInfo
    OnVerifyPeer = IdSecIOHandlerSocketOpenSSL1VerifyPeer
    Left = 80
    Top = 112
  end
end
