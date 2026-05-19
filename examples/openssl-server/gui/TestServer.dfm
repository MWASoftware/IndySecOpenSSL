object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Example OpenSSL Server'
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
    Top = 24
    Width = 609
    Height = 377
    Anchors = [akLeft, akTop, akRight, akBottom]
    Lines.Strings = (
      'Memo1')
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object Button1: TButton
    Left = 272
    Top = 412
    Width = 75
    Height = 25
    Anchors = [akLeft, akRight, akBottom]
    Caption = 'Close'
    TabOrder = 1
    OnClick = Button1Click
  end
  object IdHTTPServer1: TIdHTTPServer
    Bindings = <>
    DefaultPort = 8080
    OnQuerySSLPort = IdHTTPServer1QuerySSLPort
    OnCommandGet = IdHTTPServer1CommandGet
    Left = 96
    Top = 72
  end
  object IdHTTP1: TIdHTTP
    ProxyParams.BasicAuthentication = False
    ProxyParams.ProxyPort = 0
    Request.CharSet = 'utf-8'
    Request.ContentLength = -1
    Request.ContentRangeEnd = -1
    Request.ContentRangeStart = -1
    Request.ContentRangeInstanceLength = -1
    Request.ContentType = 'text/html'
    Request.Accept = 'application/txt'
    Request.BasicAuthentication = False
    Request.UserAgent = 'Mozilla/3.0 (compatible; Indy Library)'
    Request.Ranges.Units = 'bytes'
    Request.Ranges = <>
    HTTPOptions = [hoKeepOrigProtocol, hoNoProtocolErrorException, hoWantProtocolErrorContent]
    Left = 344
    Top = 80
  end
end
